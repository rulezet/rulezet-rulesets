rule TTP_XOR_QUAD_CurrentVersionRun_bd1b {
  strings:
    $key_bd1b = { ee 74 [2] ca 7a [2] e1 56 [2] cf 74 [2] db 6f [2] d4 75 [2] ca 68 [2] c8 69 [2] d3 6f [2] cf 68 [2] d3 47 }

  condition:
    any of them
}