rule TTP_XOR_QUAD_CurrentVersionRun_9ad2 {
  strings:
    $key_9ad2 = { c9 bd [2] ed b3 [2] c6 9f [2] e8 bd [2] fc a6 [2] f3 bc [2] ed a1 [2] ef a0 [2] f4 a6 [2] e8 a1 [2] f4 8e }

  condition:
    any of them
}