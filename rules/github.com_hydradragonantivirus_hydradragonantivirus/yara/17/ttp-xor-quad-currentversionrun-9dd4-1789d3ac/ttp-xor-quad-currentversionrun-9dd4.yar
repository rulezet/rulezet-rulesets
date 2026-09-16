rule TTP_XOR_QUAD_CurrentVersionRun_9dd4 {
  strings:
    $key_9dd4 = { ce bb [2] ea b5 [2] c1 99 [2] ef bb [2] fb a0 [2] f4 ba [2] ea a7 [2] e8 a6 [2] f3 a0 [2] ef a7 [2] f3 88 }

  condition:
    any of them
}