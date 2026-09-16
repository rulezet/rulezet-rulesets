rule TTP_XOR_QUAD_CurrentVersionRun_86a6 {
  strings:
    $key_86a6 = { d5 c9 [2] f1 c7 [2] da eb [2] f4 c9 [2] e0 d2 [2] ef c8 [2] f1 d5 [2] f3 d4 [2] e8 d2 [2] f4 d5 [2] e8 fa }

  condition:
    any of them
}