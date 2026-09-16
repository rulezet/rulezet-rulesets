rule TTP_XOR_QUAD_CurrentVersionRun_8679 {
  strings:
    $key_8679 = { d5 16 [2] f1 18 [2] da 34 [2] f4 16 [2] e0 0d [2] ef 17 [2] f1 0a [2] f3 0b [2] e8 0d [2] f4 0a [2] e8 25 }

  condition:
    any of them
}