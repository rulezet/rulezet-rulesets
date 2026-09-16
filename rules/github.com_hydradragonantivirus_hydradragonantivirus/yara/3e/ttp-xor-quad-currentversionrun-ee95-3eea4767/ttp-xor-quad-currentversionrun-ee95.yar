rule TTP_XOR_QUAD_CurrentVersionRun_ee95 {
  strings:
    $key_ee95 = { bd fa [2] 99 f4 [2] b2 d8 [2] 9c fa [2] 88 e1 [2] 87 fb [2] 99 e6 [2] 9b e7 [2] 80 e1 [2] 9c e6 [2] 80 c9 }

  condition:
    any of them
}