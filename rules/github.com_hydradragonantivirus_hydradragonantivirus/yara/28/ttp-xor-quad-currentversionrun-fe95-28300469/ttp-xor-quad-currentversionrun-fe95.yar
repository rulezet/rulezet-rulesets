rule TTP_XOR_QUAD_CurrentVersionRun_fe95 {
  strings:
    $key_fe95 = { ad fa [2] 89 f4 [2] a2 d8 [2] 8c fa [2] 98 e1 [2] 97 fb [2] 89 e6 [2] 8b e7 [2] 90 e1 [2] 8c e6 [2] 90 c9 }

  condition:
    any of them
}