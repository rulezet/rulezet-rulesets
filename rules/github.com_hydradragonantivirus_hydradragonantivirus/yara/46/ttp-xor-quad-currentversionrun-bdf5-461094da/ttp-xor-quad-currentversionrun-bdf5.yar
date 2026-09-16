rule TTP_XOR_QUAD_CurrentVersionRun_bdf5 {
  strings:
    $key_bdf5 = { ee 9a [2] ca 94 [2] e1 b8 [2] cf 9a [2] db 81 [2] d4 9b [2] ca 86 [2] c8 87 [2] d3 81 [2] cf 86 [2] d3 a9 }

  condition:
    any of them
}