rule TTP_XOR_QUAD_CurrentVersionRun_83d3 {
  strings:
    $key_83d3 = { d0 bc [2] f4 b2 [2] df 9e [2] f1 bc [2] e5 a7 [2] ea bd [2] f4 a0 [2] f6 a1 [2] ed a7 [2] f1 a0 [2] ed 8f }

  condition:
    any of them
}