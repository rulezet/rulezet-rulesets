rule TTP_XOR_QUAD_CurrentVersionRun_bd55 {
  strings:
    $key_bd55 = { ee 3a [2] ca 34 [2] e1 18 [2] cf 3a [2] db 21 [2] d4 3b [2] ca 26 [2] c8 27 [2] d3 21 [2] cf 26 [2] d3 09 }

  condition:
    any of them
}