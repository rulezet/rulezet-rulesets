rule TTP_XOR_QUAD_CurrentVersionRun_83a6 {
  strings:
    $key_83a6 = { d0 c9 [2] f4 c7 [2] df eb [2] f1 c9 [2] e5 d2 [2] ea c8 [2] f4 d5 [2] f6 d4 [2] ed d2 [2] f1 d5 [2] ed fa }

  condition:
    any of them
}