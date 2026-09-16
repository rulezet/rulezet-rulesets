rule TTP_XOR_QUAD_CurrentVersionRun_b7c2 {
  strings:
    $key_b7c2 = { e4 ad [2] c0 a3 [2] eb 8f [2] c5 ad [2] d1 b6 [2] de ac [2] c0 b1 [2] c2 b0 [2] d9 b6 [2] c5 b1 [2] d9 9e }

  condition:
    any of them
}