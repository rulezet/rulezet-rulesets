rule TTP_XOR_QUAD_CurrentVersionRun_b685 {
  strings:
    $key_b685 = { e5 ea [2] c1 e4 [2] ea c8 [2] c4 ea [2] d0 f1 [2] df eb [2] c1 f6 [2] c3 f7 [2] d8 f1 [2] c4 f6 [2] d8 d9 }

  condition:
    any of them
}