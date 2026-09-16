rule TTP_XOR_QUAD_CurrentVersionRun_8dd3 {
  strings:
    $key_8dd3 = { de bc [2] fa b2 [2] d1 9e [2] ff bc [2] eb a7 [2] e4 bd [2] fa a0 [2] f8 a1 [2] e3 a7 [2] ff a0 [2] e3 8f }

  condition:
    any of them
}