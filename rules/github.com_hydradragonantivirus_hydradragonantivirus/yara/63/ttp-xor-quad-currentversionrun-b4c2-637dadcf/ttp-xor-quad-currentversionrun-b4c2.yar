rule TTP_XOR_QUAD_CurrentVersionRun_b4c2 {
  strings:
    $key_b4c2 = { e7 ad [2] c3 a3 [2] e8 8f [2] c6 ad [2] d2 b6 [2] dd ac [2] c3 b1 [2] c1 b0 [2] da b6 [2] c6 b1 [2] da 9e }

  condition:
    any of them
}