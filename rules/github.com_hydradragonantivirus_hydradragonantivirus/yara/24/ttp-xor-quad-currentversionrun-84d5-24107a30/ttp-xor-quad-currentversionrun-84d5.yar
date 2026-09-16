rule TTP_XOR_QUAD_CurrentVersionRun_84d5 {
  strings:
    $key_84d5 = { d7 ba [2] f3 b4 [2] d8 98 [2] f6 ba [2] e2 a1 [2] ed bb [2] f3 a6 [2] f1 a7 [2] ea a1 [2] f6 a6 [2] ea 89 }

  condition:
    any of them
}