rule TTP_XOR_QUAD_CurrentVersionRun_8639 {
  strings:
    $key_8639 = { d5 56 [2] f1 58 [2] da 74 [2] f4 56 [2] e0 4d [2] ef 57 [2] f1 4a [2] f3 4b [2] e8 4d [2] f4 4a [2] e8 65 }

  condition:
    any of them
}