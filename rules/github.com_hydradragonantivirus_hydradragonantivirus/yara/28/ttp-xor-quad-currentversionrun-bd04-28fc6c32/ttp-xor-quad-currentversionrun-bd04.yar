rule TTP_XOR_QUAD_CurrentVersionRun_bd04 {
  strings:
    $key_bd04 = { ee 6b [2] ca 65 [2] e1 49 [2] cf 6b [2] db 70 [2] d4 6a [2] ca 77 [2] c8 76 [2] d3 70 [2] cf 77 [2] d3 58 }

  condition:
    any of them
}