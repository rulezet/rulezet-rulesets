rule TTP_XOR_QUAD_CurrentVersionRun_bdea {
  strings:
    $key_bdea = { ee 85 [2] ca 8b [2] e1 a7 [2] cf 85 [2] db 9e [2] d4 84 [2] ca 99 [2] c8 98 [2] d3 9e [2] cf 99 [2] d3 b6 }

  condition:
    any of them
}