rule TTP_XOR_QUAD_CurrentVersionRun_bcdf {
  strings:
    $key_bcdf = { ef b0 [2] cb be [2] e0 92 [2] ce b0 [2] da ab [2] d5 b1 [2] cb ac [2] c9 ad [2] d2 ab [2] ce ac [2] d2 83 }

  condition:
    any of them
}