rule TTP_XOR_QUAD_CurrentVersionRun_a785 {
  strings:
    $key_a785 = { f4 ea [2] d0 e4 [2] fb c8 [2] d5 ea [2] c1 f1 [2] ce eb [2] d0 f6 [2] d2 f7 [2] c9 f1 [2] d5 f6 [2] c9 d9 }

  condition:
    any of them
}