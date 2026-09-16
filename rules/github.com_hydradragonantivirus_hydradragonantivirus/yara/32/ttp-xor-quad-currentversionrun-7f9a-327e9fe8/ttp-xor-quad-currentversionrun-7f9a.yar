rule TTP_XOR_QUAD_CurrentVersionRun_7f9a {
  strings:
    $key_7f9a = { 2c f5 [2] 08 fb [2] 23 d7 [2] 0d f5 [2] 19 ee [2] 16 f4 [2] 08 e9 [2] 0a e8 [2] 11 ee [2] 0d e9 [2] 11 c6 }

  condition:
    any of them
}