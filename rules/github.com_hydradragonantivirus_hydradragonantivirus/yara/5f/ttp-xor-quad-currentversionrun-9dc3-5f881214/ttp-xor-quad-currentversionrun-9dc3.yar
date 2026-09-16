rule TTP_XOR_QUAD_CurrentVersionRun_9dc3 {
  strings:
    $key_9dc3 = { ce ac [2] ea a2 [2] c1 8e [2] ef ac [2] fb b7 [2] f4 ad [2] ea b0 [2] e8 b1 [2] f3 b7 [2] ef b0 [2] f3 9f }

  condition:
    any of them
}