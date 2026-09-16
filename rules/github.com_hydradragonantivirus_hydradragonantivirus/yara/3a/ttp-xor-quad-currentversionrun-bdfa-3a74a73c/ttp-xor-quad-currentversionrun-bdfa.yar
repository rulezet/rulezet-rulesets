rule TTP_XOR_QUAD_CurrentVersionRun_bdfa {
  strings:
    $key_bdfa = { ee 95 [2] ca 9b [2] e1 b7 [2] cf 95 [2] db 8e [2] d4 94 [2] ca 89 [2] c8 88 [2] d3 8e [2] cf 89 [2] d3 a6 }

  condition:
    any of them
}