rule TTP_XOR_QUAD_CurrentVersionRun_83b7 {
  strings:
    $key_83b7 = { d0 d8 [2] f4 d6 [2] df fa [2] f1 d8 [2] e5 c3 [2] ea d9 [2] f4 c4 [2] f6 c5 [2] ed c3 [2] f1 c4 [2] ed eb }

  condition:
    any of them
}