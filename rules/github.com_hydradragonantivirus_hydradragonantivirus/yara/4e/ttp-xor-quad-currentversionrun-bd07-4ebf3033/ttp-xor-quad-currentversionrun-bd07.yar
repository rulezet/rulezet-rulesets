rule TTP_XOR_QUAD_CurrentVersionRun_bd07 {
  strings:
    $key_bd07 = { ee 68 [2] ca 66 [2] e1 4a [2] cf 68 [2] db 73 [2] d4 69 [2] ca 74 [2] c8 75 [2] d3 73 [2] cf 74 [2] d3 5b }

  condition:
    any of them
}