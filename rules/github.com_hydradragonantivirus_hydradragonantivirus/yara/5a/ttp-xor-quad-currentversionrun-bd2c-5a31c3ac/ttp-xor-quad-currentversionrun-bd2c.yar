rule TTP_XOR_QUAD_CurrentVersionRun_bd2c {
  strings:
    $key_bd2c = { ee 43 [2] ca 4d [2] e1 61 [2] cf 43 [2] db 58 [2] d4 42 [2] ca 5f [2] c8 5e [2] d3 58 [2] cf 5f [2] d3 70 }

  condition:
    any of them
}