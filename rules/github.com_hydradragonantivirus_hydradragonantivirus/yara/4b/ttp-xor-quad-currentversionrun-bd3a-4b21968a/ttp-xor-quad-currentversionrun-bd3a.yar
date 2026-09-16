rule TTP_XOR_QUAD_CurrentVersionRun_bd3a {
  strings:
    $key_bd3a = { ee 55 [2] ca 5b [2] e1 77 [2] cf 55 [2] db 4e [2] d4 54 [2] ca 49 [2] c8 48 [2] d3 4e [2] cf 49 [2] d3 66 }

  condition:
    any of them
}