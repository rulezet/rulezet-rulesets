rule TTP_XOR_QUAD_CurrentVersionRun_9d86 {
  strings:
    $key_9d86 = { ce e9 [2] ea e7 [2] c1 cb [2] ef e9 [2] fb f2 [2] f4 e8 [2] ea f5 [2] e8 f4 [2] f3 f2 [2] ef f5 [2] f3 da }

  condition:
    any of them
}