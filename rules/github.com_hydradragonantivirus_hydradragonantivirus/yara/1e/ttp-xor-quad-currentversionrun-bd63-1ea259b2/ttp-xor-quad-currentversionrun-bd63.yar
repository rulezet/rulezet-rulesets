rule TTP_XOR_QUAD_CurrentVersionRun_bd63 {
  strings:
    $key_bd63 = { ee 0c [2] ca 02 [2] e1 2e [2] cf 0c [2] db 17 [2] d4 0d [2] ca 10 [2] c8 11 [2] d3 17 [2] cf 10 [2] d3 3f }

  condition:
    any of them
}