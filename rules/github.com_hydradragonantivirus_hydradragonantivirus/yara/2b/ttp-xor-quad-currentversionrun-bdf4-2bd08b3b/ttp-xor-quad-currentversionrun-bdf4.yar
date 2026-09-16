rule TTP_XOR_QUAD_CurrentVersionRun_bdf4 {
  strings:
    $key_bdf4 = { ee 9b [2] ca 95 [2] e1 b9 [2] cf 9b [2] db 80 [2] d4 9a [2] ca 87 [2] c8 86 [2] d3 80 [2] cf 87 [2] d3 a8 }

  condition:
    any of them
}