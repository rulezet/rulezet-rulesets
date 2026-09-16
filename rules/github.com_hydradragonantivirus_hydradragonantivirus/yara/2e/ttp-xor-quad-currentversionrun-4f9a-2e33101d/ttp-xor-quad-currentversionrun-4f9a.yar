rule TTP_XOR_QUAD_CurrentVersionRun_4f9a {
  strings:
    $key_4f9a = { 1c f5 [2] 38 fb [2] 13 d7 [2] 3d f5 [2] 29 ee [2] 26 f4 [2] 38 e9 [2] 3a e8 [2] 21 ee [2] 3d e9 [2] 21 c6 }

  condition:
    any of them
}