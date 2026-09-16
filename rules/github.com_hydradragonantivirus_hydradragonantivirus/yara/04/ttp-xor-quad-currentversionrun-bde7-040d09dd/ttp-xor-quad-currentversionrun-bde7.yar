rule TTP_XOR_QUAD_CurrentVersionRun_bde7 {
  strings:
    $key_bde7 = { ee 88 [2] ca 86 [2] e1 aa [2] cf 88 [2] db 93 [2] d4 89 [2] ca 94 [2] c8 95 [2] d3 93 [2] cf 94 [2] d3 bb }

  condition:
    any of them
}