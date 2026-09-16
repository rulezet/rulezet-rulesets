rule TTP_XOR_QUAD_CurrentVersionRun_9ad7 {
  strings:
    $key_9ad7 = { c9 b8 [2] ed b6 [2] c6 9a [2] e8 b8 [2] fc a3 [2] f3 b9 [2] ed a4 [2] ef a5 [2] f4 a3 [2] e8 a4 [2] f4 8b }

  condition:
    any of them
}