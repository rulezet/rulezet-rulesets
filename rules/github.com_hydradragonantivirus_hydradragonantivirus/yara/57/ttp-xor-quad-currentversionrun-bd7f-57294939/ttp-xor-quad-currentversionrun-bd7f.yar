rule TTP_XOR_QUAD_CurrentVersionRun_bd7f {
  strings:
    $key_bd7f = { ee 10 [2] ca 1e [2] e1 32 [2] cf 10 [2] db 0b [2] d4 11 [2] ca 0c [2] c8 0d [2] d3 0b [2] cf 0c [2] d3 23 }

  condition:
    any of them
}