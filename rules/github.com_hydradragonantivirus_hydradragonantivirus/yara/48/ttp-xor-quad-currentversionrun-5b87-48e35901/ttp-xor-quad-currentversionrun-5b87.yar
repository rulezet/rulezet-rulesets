rule TTP_XOR_QUAD_CurrentVersionRun_5b87 {
  strings:
    $key_5b87 = { 08 e8 [2] 2c e6 [2] 07 ca [2] 29 e8 [2] 3d f3 [2] 32 e9 [2] 2c f4 [2] 2e f5 [2] 35 f3 [2] 29 f4 [2] 35 db }

  condition:
    any of them
}