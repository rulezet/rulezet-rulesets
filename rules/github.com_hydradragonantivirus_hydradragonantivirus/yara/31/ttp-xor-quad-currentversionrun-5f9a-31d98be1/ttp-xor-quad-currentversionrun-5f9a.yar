rule TTP_XOR_QUAD_CurrentVersionRun_5f9a {
  strings:
    $key_5f9a = { 0c f5 [2] 28 fb [2] 03 d7 [2] 2d f5 [2] 39 ee [2] 36 f4 [2] 28 e9 [2] 2a e8 [2] 31 ee [2] 2d e9 [2] 31 c6 }

  condition:
    any of them
}