rule TTP_XOR_QUAD_CurrentVersionRun_83b6 {
  strings:
    $key_83b6 = { d0 d9 [2] f4 d7 [2] df fb [2] f1 d9 [2] e5 c2 [2] ea d8 [2] f4 c5 [2] f6 c4 [2] ed c2 [2] f1 c5 [2] ed ea }

  condition:
    any of them
}