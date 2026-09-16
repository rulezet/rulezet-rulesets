rule TTP_XOR_QUAD_CurrentVersionRun_ab84 {
  strings:
    $key_ab84 = { f8 eb [2] dc e5 [2] f7 c9 [2] d9 eb [2] cd f0 [2] c2 ea [2] dc f7 [2] de f6 [2] c5 f0 [2] d9 f7 [2] c5 d8 }

  condition:
    any of them
}