rule TTP_XOR_QUAD_CurrentVersionRun_bd1a {
  strings:
    $key_bd1a = { ee 75 [2] ca 7b [2] e1 57 [2] cf 75 [2] db 6e [2] d4 74 [2] ca 69 [2] c8 68 [2] d3 6e [2] cf 69 [2] d3 46 }

  condition:
    any of them
}