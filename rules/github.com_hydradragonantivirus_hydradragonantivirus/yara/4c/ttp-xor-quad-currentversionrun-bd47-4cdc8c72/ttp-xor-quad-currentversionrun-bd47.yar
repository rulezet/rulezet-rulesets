rule TTP_XOR_QUAD_CurrentVersionRun_bd47 {
  strings:
    $key_bd47 = { ee 28 [2] ca 26 [2] e1 0a [2] cf 28 [2] db 33 [2] d4 29 [2] ca 34 [2] c8 35 [2] d3 33 [2] cf 34 [2] d3 1b }

  condition:
    any of them
}