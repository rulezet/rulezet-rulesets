rule TTP_XOR_QUAD_CurrentVersionRun_bd73 {
  strings:
    $key_bd73 = { ee 1c [2] ca 12 [2] e1 3e [2] cf 1c [2] db 07 [2] d4 1d [2] ca 00 [2] c8 01 [2] d3 07 [2] cf 00 [2] d3 2f }

  condition:
    any of them
}