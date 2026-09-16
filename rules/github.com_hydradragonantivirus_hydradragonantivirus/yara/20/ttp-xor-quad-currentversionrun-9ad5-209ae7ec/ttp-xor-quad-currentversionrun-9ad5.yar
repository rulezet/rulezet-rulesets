rule TTP_XOR_QUAD_CurrentVersionRun_9ad5 {
  strings:
    $key_9ad5 = { c9 ba [2] ed b4 [2] c6 98 [2] e8 ba [2] fc a1 [2] f3 bb [2] ed a6 [2] ef a7 [2] f4 a1 [2] e8 a6 [2] f4 89 }

  condition:
    any of them
}