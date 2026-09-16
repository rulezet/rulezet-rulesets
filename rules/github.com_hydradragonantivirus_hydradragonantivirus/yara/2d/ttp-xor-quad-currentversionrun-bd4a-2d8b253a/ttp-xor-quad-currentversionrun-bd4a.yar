rule TTP_XOR_QUAD_CurrentVersionRun_bd4a {
  strings:
    $key_bd4a = { ee 25 [2] ca 2b [2] e1 07 [2] cf 25 [2] db 3e [2] d4 24 [2] ca 39 [2] c8 38 [2] d3 3e [2] cf 39 [2] d3 16 }

  condition:
    any of them
}