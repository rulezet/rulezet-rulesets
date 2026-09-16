rule TTP_XOR_QUAD_CurrentVersionRun_9dd5 {
  strings:
    $key_9dd5 = { ce ba [2] ea b4 [2] c1 98 [2] ef ba [2] fb a1 [2] f4 bb [2] ea a6 [2] e8 a7 [2] f3 a1 [2] ef a6 [2] f3 89 }

  condition:
    any of them
}