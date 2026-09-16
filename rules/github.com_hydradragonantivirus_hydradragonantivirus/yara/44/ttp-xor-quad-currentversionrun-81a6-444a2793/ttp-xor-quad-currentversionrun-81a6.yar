rule TTP_XOR_QUAD_CurrentVersionRun_81a6 {
  strings:
    $key_81a6 = { d2 c9 [2] f6 c7 [2] dd eb [2] f3 c9 [2] e7 d2 [2] e8 c8 [2] f6 d5 [2] f4 d4 [2] ef d2 [2] f3 d5 [2] ef fa }

  condition:
    any of them
}