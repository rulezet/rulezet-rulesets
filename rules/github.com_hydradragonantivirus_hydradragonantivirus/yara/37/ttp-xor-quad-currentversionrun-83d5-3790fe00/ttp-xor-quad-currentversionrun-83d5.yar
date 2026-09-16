rule TTP_XOR_QUAD_CurrentVersionRun_83d5 {
  strings:
    $key_83d5 = { d0 ba [2] f4 b4 [2] df 98 [2] f1 ba [2] e5 a1 [2] ea bb [2] f4 a6 [2] f6 a7 [2] ed a1 [2] f1 a6 [2] ed 89 }

  condition:
    any of them
}