rule TTP_XOR_QUAD_CurrentVersionRun_bded {
  strings:
    $key_bded = { ee 82 [2] ca 8c [2] e1 a0 [2] cf 82 [2] db 99 [2] d4 83 [2] ca 9e [2] c8 9f [2] d3 99 [2] cf 9e [2] d3 b1 }

  condition:
    any of them
}