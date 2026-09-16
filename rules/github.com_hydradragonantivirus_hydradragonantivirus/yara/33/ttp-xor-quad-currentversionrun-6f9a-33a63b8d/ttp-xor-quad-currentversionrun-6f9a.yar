rule TTP_XOR_QUAD_CurrentVersionRun_6f9a {
  strings:
    $key_6f9a = { 3c f5 [2] 18 fb [2] 33 d7 [2] 1d f5 [2] 09 ee [2] 06 f4 [2] 18 e9 [2] 1a e8 [2] 01 ee [2] 1d e9 [2] 01 c6 }

  condition:
    any of them
}