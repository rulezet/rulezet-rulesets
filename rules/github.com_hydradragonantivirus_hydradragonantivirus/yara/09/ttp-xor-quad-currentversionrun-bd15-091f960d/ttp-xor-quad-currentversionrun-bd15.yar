rule TTP_XOR_QUAD_CurrentVersionRun_bd15 {
  strings:
    $key_bd15 = { ee 7a [2] ca 74 [2] e1 58 [2] cf 7a [2] db 61 [2] d4 7b [2] ca 66 [2] c8 67 [2] d3 61 [2] cf 66 [2] d3 49 }

  condition:
    any of them
}