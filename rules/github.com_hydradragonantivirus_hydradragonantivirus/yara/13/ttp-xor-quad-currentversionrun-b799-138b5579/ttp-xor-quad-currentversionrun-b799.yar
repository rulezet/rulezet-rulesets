rule TTP_XOR_QUAD_CurrentVersionRun_b799 {
  strings:
    $key_b799 = { e4 f6 [2] c0 f8 [2] eb d4 [2] c5 f6 [2] d1 ed [2] de f7 [2] c0 ea [2] c2 eb [2] d9 ed [2] c5 ea [2] d9 c5 }

  condition:
    any of them
}