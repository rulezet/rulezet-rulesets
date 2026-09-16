rule TTP_XOR_QUAD_CurrentVersionRun_9dd3 {
  strings:
    $key_9dd3 = { ce bc [2] ea b2 [2] c1 9e [2] ef bc [2] fb a7 [2] f4 bd [2] ea a0 [2] e8 a1 [2] f3 a7 [2] ef a0 [2] f3 8f }

  condition:
    any of them
}