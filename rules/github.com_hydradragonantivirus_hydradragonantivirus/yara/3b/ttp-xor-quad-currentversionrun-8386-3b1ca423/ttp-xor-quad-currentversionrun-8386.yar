rule TTP_XOR_QUAD_CurrentVersionRun_8386 {
  strings:
    $key_8386 = { d0 e9 [2] f4 e7 [2] df cb [2] f1 e9 [2] e5 f2 [2] ea e8 [2] f4 f5 [2] f6 f4 [2] ed f2 [2] f1 f5 [2] ed da }

  condition:
    any of them
}