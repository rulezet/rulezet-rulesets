rule TTP_XOR_QUAD_CurrentVersionRun_bd24 {
  strings:
    $key_bd24 = { ee 4b [2] ca 45 [2] e1 69 [2] cf 4b [2] db 50 [2] d4 4a [2] ca 57 [2] c8 56 [2] d3 50 [2] cf 57 [2] d3 78 }

  condition:
    any of them
}