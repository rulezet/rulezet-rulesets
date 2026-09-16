rule TTP_XOR_QUAD_CurrentVersionRun_bdf8 {
  strings:
    $key_bdf8 = { ee 97 [2] ca 99 [2] e1 b5 [2] cf 97 [2] db 8c [2] d4 96 [2] ca 8b [2] c8 8a [2] d3 8c [2] cf 8b [2] d3 a4 }

  condition:
    any of them
}