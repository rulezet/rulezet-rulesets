rule TTP_XOR_QUAD_CurrentVersionRun_b7c5 {
  strings:
    $key_b7c5 = { e4 aa [2] c0 a4 [2] eb 88 [2] c5 aa [2] d1 b1 [2] de ab [2] c0 b6 [2] c2 b7 [2] d9 b1 [2] c5 b6 [2] d9 99 }

  condition:
    any of them
}