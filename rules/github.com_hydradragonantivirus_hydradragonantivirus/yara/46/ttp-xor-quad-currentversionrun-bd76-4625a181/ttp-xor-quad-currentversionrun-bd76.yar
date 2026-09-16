rule TTP_XOR_QUAD_CurrentVersionRun_bd76 {
  strings:
    $key_bd76 = { ee 19 [2] ca 17 [2] e1 3b [2] cf 19 [2] db 02 [2] d4 18 [2] ca 05 [2] c8 04 [2] d3 02 [2] cf 05 [2] d3 2a }

  condition:
    any of them
}