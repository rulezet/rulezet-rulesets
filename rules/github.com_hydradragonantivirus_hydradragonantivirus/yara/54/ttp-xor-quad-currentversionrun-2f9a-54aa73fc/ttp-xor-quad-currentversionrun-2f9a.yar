rule TTP_XOR_QUAD_CurrentVersionRun_2f9a {
  strings:
    $key_2f9a = { 7c f5 [2] 58 fb [2] 73 d7 [2] 5d f5 [2] 49 ee [2] 46 f4 [2] 58 e9 [2] 5a e8 [2] 41 ee [2] 5d e9 [2] 41 c6 }

  condition:
    any of them
}