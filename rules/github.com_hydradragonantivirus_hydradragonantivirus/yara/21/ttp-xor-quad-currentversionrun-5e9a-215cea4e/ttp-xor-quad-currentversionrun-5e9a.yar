rule TTP_XOR_QUAD_CurrentVersionRun_5e9a {
  strings:
    $key_5e9a = { 0d f5 [2] 29 fb [2] 02 d7 [2] 2c f5 [2] 38 ee [2] 37 f4 [2] 29 e9 [2] 2b e8 [2] 30 ee [2] 2c e9 [2] 30 c6 }

  condition:
    any of them
}