rule TTP_XOR_QUAD_CurrentVersionRun_bd65 {
  strings:
    $key_bd65 = { ee 0a [2] ca 04 [2] e1 28 [2] cf 0a [2] db 11 [2] d4 0b [2] ca 16 [2] c8 17 [2] d3 11 [2] cf 16 [2] d3 39 }

  condition:
    any of them
}