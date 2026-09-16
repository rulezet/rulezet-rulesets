rule TTP_XOR_QUAD_CurrentVersionRun_bdf9 {
  strings:
    $key_bdf9 = { ee 96 [2] ca 98 [2] e1 b4 [2] cf 96 [2] db 8d [2] d4 97 [2] ca 8a [2] c8 8b [2] d3 8d [2] cf 8a [2] d3 a5 }

  condition:
    any of them
}