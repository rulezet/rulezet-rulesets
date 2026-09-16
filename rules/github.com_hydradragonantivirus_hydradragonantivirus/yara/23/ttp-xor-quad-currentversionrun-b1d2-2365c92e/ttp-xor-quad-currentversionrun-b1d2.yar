rule TTP_XOR_QUAD_CurrentVersionRun_b1d2 {
  strings:
    $key_b1d2 = { e2 bd [2] c6 b3 [2] ed 9f [2] c3 bd [2] d7 a6 [2] d8 bc [2] c6 a1 [2] c4 a0 [2] df a6 [2] c3 a1 [2] df 8e }

  condition:
    any of them
}