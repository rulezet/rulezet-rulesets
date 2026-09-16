rule TTP_XOR_QUAD_CurrentVersionRun_2e9a {
  strings:
    $key_2e9a = { 7d f5 [2] 59 fb [2] 72 d7 [2] 5c f5 [2] 48 ee [2] 47 f4 [2] 59 e9 [2] 5b e8 [2] 40 ee [2] 5c e9 [2] 40 c6 }

  condition:
    any of them
}