rule TTP_XOR_QUAD_CurrentVersionRun_bd79 {
  strings:
    $key_bd79 = { ee 16 [2] ca 18 [2] e1 34 [2] cf 16 [2] db 0d [2] d4 17 [2] ca 0a [2] c8 0b [2] d3 0d [2] cf 0a [2] d3 25 }

  condition:
    any of them
}