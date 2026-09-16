rule TTP_XOR_QUAD_CurrentVersionRun_bd14 {
  strings:
    $key_bd14 = { ee 7b [2] ca 75 [2] e1 59 [2] cf 7b [2] db 60 [2] d4 7a [2] ca 67 [2] c8 66 [2] d3 60 [2] cf 67 [2] d3 48 }

  condition:
    any of them
}