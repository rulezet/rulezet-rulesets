rule TTP_XOR_QUAD_CurrentVersionRun_fe9a {
  strings:
    $key_fe9a = { ad f5 [2] 89 fb [2] a2 d7 [2] 8c f5 [2] 98 ee [2] 97 f4 [2] 89 e9 [2] 8b e8 [2] 90 ee [2] 8c e9 [2] 90 c6 }

  condition:
    any of them
}