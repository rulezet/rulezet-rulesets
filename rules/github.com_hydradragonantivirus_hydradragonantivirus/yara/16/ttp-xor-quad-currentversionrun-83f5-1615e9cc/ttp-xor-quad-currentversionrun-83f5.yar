rule TTP_XOR_QUAD_CurrentVersionRun_83f5 {
  strings:
    $key_83f5 = { d0 9a [2] f4 94 [2] df b8 [2] f1 9a [2] e5 81 [2] ea 9b [2] f4 86 [2] f6 87 [2] ed 81 [2] f1 86 [2] ed a9 }

  condition:
    any of them
}