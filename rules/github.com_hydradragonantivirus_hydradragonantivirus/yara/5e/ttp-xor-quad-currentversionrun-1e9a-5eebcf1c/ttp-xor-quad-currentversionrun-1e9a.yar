rule TTP_XOR_QUAD_CurrentVersionRun_1e9a {
  strings:
    $key_1e9a = { 4d f5 [2] 69 fb [2] 42 d7 [2] 6c f5 [2] 78 ee [2] 77 f4 [2] 69 e9 [2] 6b e8 [2] 70 ee [2] 6c e9 [2] 70 c6 }

  condition:
    any of them
}