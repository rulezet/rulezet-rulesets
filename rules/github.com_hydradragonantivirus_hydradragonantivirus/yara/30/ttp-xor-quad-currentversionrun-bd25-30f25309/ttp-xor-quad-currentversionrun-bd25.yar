rule TTP_XOR_QUAD_CurrentVersionRun_bd25 {
  strings:
    $key_bd25 = { ee 4a [2] ca 44 [2] e1 68 [2] cf 4a [2] db 51 [2] d4 4b [2] ca 56 [2] c8 57 [2] d3 51 [2] cf 56 [2] d3 79 }

  condition:
    any of them
}