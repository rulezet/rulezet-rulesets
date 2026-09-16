rule TTP_XOR_QUAD_CurrentVersionRun_bdfc {
  strings:
    $key_bdfc = { ee 93 [2] ca 9d [2] e1 b1 [2] cf 93 [2] db 88 [2] d4 92 [2] ca 8f [2] c8 8e [2] d3 88 [2] cf 8f [2] d3 a0 }

  condition:
    any of them
}