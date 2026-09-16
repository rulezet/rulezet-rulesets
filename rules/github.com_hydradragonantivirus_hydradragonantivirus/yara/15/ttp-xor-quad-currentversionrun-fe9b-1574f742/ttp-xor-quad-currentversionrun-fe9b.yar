rule TTP_XOR_QUAD_CurrentVersionRun_fe9b {
  strings:
    $key_fe9b = { ad f4 [2] 89 fa [2] a2 d6 [2] 8c f4 [2] 98 ef [2] 97 f5 [2] 89 e8 [2] 8b e9 [2] 90 ef [2] 8c e8 [2] 90 c7 }

  condition:
    any of them
}