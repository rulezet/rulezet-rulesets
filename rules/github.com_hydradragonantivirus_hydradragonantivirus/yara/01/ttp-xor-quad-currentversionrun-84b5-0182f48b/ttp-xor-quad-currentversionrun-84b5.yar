rule TTP_XOR_QUAD_CurrentVersionRun_84b5 {
  strings:
    $key_84b5 = { d7 da [2] f3 d4 [2] d8 f8 [2] f6 da [2] e2 c1 [2] ed db [2] f3 c6 [2] f1 c7 [2] ea c1 [2] f6 c6 [2] ea e9 }

  condition:
    any of them
}