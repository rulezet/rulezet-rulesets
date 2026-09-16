rule TTP_XOR_QUAD_CurrentVersionRun_bd60 {
  strings:
    $key_bd60 = { ee 0f [2] ca 01 [2] e1 2d [2] cf 0f [2] db 14 [2] d4 0e [2] ca 13 [2] c8 12 [2] d3 14 [2] cf 13 [2] d3 3c }

  condition:
    any of them
}