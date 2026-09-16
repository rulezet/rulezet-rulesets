rule TTP_XOR_QUAD_CurrentVersionRun_b3c2 {
  strings:
    $key_b3c2 = { e0 ad [2] c4 a3 [2] ef 8f [2] c1 ad [2] d5 b6 [2] da ac [2] c4 b1 [2] c6 b0 [2] dd b6 [2] c1 b1 [2] dd 9e }

  condition:
    any of them
}