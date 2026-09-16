rule TTP_XOR_QUAD_CurrentVersionRun_5b9a {
  strings:
    $key_5b9a = { 08 f5 [2] 2c fb [2] 07 d7 [2] 29 f5 [2] 3d ee [2] 32 f4 [2] 2c e9 [2] 2e e8 [2] 35 ee [2] 29 e9 [2] 35 c6 }

  condition:
    any of them
}