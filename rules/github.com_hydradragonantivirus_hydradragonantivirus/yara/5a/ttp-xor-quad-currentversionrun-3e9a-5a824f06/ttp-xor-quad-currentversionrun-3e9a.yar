rule TTP_XOR_QUAD_CurrentVersionRun_3e9a {
  strings:
    $key_3e9a = { 6d f5 [2] 49 fb [2] 62 d7 [2] 4c f5 [2] 58 ee [2] 57 f4 [2] 49 e9 [2] 4b e8 [2] 50 ee [2] 4c e9 [2] 50 c6 }

  condition:
    any of them
}