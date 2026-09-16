rule TTP_XOR_QUAD_CurrentVersionRun_bd59 {
  strings:
    $key_bd59 = { ee 36 [2] ca 38 [2] e1 14 [2] cf 36 [2] db 2d [2] d4 37 [2] ca 2a [2] c8 2b [2] d3 2d [2] cf 2a [2] d3 05 }

  condition:
    any of them
}