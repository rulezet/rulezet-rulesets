rule TTP_XOR_QUAD_CurrentVersionRun_bd62 {
  strings:
    $key_bd62 = { ee 0d [2] ca 03 [2] e1 2f [2] cf 0d [2] db 16 [2] d4 0c [2] ca 11 [2] c8 10 [2] d3 16 [2] cf 11 [2] d3 3e }

  condition:
    any of them
}