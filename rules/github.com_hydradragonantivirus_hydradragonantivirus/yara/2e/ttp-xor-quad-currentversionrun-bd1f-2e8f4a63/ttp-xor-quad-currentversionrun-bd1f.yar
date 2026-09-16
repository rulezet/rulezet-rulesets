rule TTP_XOR_QUAD_CurrentVersionRun_bd1f {
  strings:
    $key_bd1f = { ee 70 [2] ca 7e [2] e1 52 [2] cf 70 [2] db 6b [2] d4 71 [2] ca 6c [2] c8 6d [2] d3 6b [2] cf 6c [2] d3 43 }

  condition:
    any of them
}