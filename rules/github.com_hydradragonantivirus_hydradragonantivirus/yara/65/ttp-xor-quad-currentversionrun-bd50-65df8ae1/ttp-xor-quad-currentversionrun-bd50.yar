rule TTP_XOR_QUAD_CurrentVersionRun_bd50 {
  strings:
    $key_bd50 = { ee 3f [2] ca 31 [2] e1 1d [2] cf 3f [2] db 24 [2] d4 3e [2] ca 23 [2] c8 22 [2] d3 24 [2] cf 23 [2] d3 0c }

  condition:
    any of them
}