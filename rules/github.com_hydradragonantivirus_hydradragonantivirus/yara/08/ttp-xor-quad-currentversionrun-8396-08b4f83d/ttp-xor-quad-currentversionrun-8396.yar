rule TTP_XOR_QUAD_CurrentVersionRun_8396 {
  strings:
    $key_8396 = { d0 f9 [2] f4 f7 [2] df db [2] f1 f9 [2] e5 e2 [2] ea f8 [2] f4 e5 [2] f6 e4 [2] ed e2 [2] f1 e5 [2] ed ca }

  condition:
    any of them
}