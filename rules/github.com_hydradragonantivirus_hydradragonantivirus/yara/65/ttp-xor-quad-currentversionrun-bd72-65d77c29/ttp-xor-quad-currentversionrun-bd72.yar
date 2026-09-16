rule TTP_XOR_QUAD_CurrentVersionRun_bd72 {
  strings:
    $key_bd72 = { ee 1d [2] ca 13 [2] e1 3f [2] cf 1d [2] db 06 [2] d4 1c [2] ca 01 [2] c8 00 [2] d3 06 [2] cf 01 [2] d3 2e }

  condition:
    any of them
}