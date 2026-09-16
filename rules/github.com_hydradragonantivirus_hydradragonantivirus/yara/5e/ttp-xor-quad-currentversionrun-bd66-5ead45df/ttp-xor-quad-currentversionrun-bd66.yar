rule TTP_XOR_QUAD_CurrentVersionRun_bd66 {
  strings:
    $key_bd66 = { ee 09 [2] ca 07 [2] e1 2b [2] cf 09 [2] db 12 [2] d4 08 [2] ca 15 [2] c8 14 [2] d3 12 [2] cf 15 [2] d3 3a }

  condition:
    any of them
}