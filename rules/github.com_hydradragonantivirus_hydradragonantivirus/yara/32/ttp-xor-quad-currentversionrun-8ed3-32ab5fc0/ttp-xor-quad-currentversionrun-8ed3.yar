rule TTP_XOR_QUAD_CurrentVersionRun_8ed3 {
  strings:
    $key_8ed3 = { dd bc [2] f9 b2 [2] d2 9e [2] fc bc [2] e8 a7 [2] e7 bd [2] f9 a0 [2] fb a1 [2] e0 a7 [2] fc a0 [2] e0 8f }

  condition:
    any of them
}