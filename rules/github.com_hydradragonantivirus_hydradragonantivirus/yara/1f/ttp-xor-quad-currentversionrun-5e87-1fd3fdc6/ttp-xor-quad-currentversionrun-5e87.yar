rule TTP_XOR_QUAD_CurrentVersionRun_5e87 {
  strings:
    $key_5e87 = { 0d e8 [2] 29 e6 [2] 02 ca [2] 2c e8 [2] 38 f3 [2] 37 e9 [2] 29 f4 [2] 2b f5 [2] 30 f3 [2] 2c f4 [2] 30 db }

  condition:
    any of them
}