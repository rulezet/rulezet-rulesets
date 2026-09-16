rule TTP_XOR_QUAD_CurrentVersionRun_84b7 {
  strings:
    $key_84b7 = { d7 d8 [2] f3 d6 [2] d8 fa [2] f6 d8 [2] e2 c3 [2] ed d9 [2] f3 c4 [2] f1 c5 [2] ea c3 [2] f6 c4 [2] ea eb }

  condition:
    any of them
}