rule TTP_XOR_QUAD_CurrentVersionRun_8625 {
  strings:
    $key_8625 = { d5 4a [2] f1 44 [2] da 68 [2] f4 4a [2] e0 51 [2] ef 4b [2] f1 56 [2] f3 57 [2] e8 51 [2] f4 56 [2] e8 79 }

  condition:
    any of them
}