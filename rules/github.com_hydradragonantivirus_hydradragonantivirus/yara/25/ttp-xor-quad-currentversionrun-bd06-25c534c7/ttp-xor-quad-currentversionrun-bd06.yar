rule TTP_XOR_QUAD_CurrentVersionRun_bd06 {
  strings:
    $key_bd06 = { ee 69 [2] ca 67 [2] e1 4b [2] cf 69 [2] db 72 [2] d4 68 [2] ca 75 [2] c8 74 [2] d3 72 [2] cf 75 [2] d3 5a }

  condition:
    any of them
}