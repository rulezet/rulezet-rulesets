rule TTP_XOR_QUAD_CurrentVersionRun_bd77 {
  strings:
    $key_bd77 = { ee 18 [2] ca 16 [2] e1 3a [2] cf 18 [2] db 03 [2] d4 19 [2] ca 04 [2] c8 05 [2] d3 03 [2] cf 04 [2] d3 2b }

  condition:
    any of them
}