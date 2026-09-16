rule TTP_XOR_QUAD_CurrentVersionRun_b785 {
  strings:
    $key_b785 = { e4 ea [2] c0 e4 [2] eb c8 [2] c5 ea [2] d1 f1 [2] de eb [2] c0 f6 [2] c2 f7 [2] d9 f1 [2] c5 f6 [2] d9 d9 }

  condition:
    any of them
}