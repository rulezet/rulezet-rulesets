rule TTP_XOR_QUAD_CurrentVersionRun_1f9a {
  strings:
    $key_1f9a = { 4c f5 [2] 68 fb [2] 43 d7 [2] 6d f5 [2] 79 ee [2] 76 f4 [2] 68 e9 [2] 6a e8 [2] 71 ee [2] 6d e9 [2] 71 c6 }

  condition:
    any of them
}