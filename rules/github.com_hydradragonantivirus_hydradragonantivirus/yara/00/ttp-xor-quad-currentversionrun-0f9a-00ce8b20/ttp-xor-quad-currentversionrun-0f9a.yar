rule TTP_XOR_QUAD_CurrentVersionRun_0f9a {
  strings:
    $key_0f9a = { 5c f5 [2] 78 fb [2] 53 d7 [2] 7d f5 [2] 69 ee [2] 66 f4 [2] 78 e9 [2] 7a e8 [2] 61 ee [2] 7d e9 [2] 61 c6 }

  condition:
    any of them
}