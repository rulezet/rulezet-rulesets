rule TTP_XOR_QUAD_CurrentVersionRun_9ad4 {
  strings:
    $key_9ad4 = { c9 bb [2] ed b5 [2] c6 99 [2] e8 bb [2] fc a0 [2] f3 ba [2] ed a7 [2] ef a6 [2] f4 a0 [2] e8 a7 [2] f4 88 }

  condition:
    any of them
}