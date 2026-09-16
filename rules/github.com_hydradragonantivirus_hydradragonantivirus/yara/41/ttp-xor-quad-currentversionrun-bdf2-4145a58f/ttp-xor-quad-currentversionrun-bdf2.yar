rule TTP_XOR_QUAD_CurrentVersionRun_bdf2 {
  strings:
    $key_bdf2 = { ee 9d [2] ca 93 [2] e1 bf [2] cf 9d [2] db 86 [2] d4 9c [2] ca 81 [2] c8 80 [2] d3 86 [2] cf 81 [2] d3 ae }

  condition:
    any of them
}