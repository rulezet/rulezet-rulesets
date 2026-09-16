rule TTP_XOR_QUAD_CurrentVersionRun_b7c7 {
  strings:
    $key_b7c7 = { e4 a8 [2] c0 a6 [2] eb 8a [2] c5 a8 [2] d1 b3 [2] de a9 [2] c0 b4 [2] c2 b5 [2] d9 b3 [2] c5 b4 [2] d9 9b }

  condition:
    any of them
}