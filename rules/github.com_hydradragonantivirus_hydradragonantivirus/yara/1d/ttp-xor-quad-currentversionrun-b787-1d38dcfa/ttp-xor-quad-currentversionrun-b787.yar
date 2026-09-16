rule TTP_XOR_QUAD_CurrentVersionRun_b787 {
  strings:
    $key_b787 = { e4 e8 [2] c0 e6 [2] eb ca [2] c5 e8 [2] d1 f3 [2] de e9 [2] c0 f4 [2] c2 f5 [2] d9 f3 [2] c5 f4 [2] d9 db }

  condition:
    any of them
}