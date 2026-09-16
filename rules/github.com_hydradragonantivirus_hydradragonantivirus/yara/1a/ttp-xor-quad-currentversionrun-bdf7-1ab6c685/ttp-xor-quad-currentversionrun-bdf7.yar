rule TTP_XOR_QUAD_CurrentVersionRun_bdf7 {
  strings:
    $key_bdf7 = { ee 98 [2] ca 96 [2] e1 ba [2] cf 98 [2] db 83 [2] d4 99 [2] ca 84 [2] c8 85 [2] d3 83 [2] cf 84 [2] d3 ab }

  condition:
    any of them
}