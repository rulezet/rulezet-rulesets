rule TTP_XOR_QUAD_CurrentVersionRun_b184 {
  strings:
    $key_b184 = { e2 eb [2] c6 e5 [2] ed c9 [2] c3 eb [2] d7 f0 [2] d8 ea [2] c6 f7 [2] c4 f6 [2] df f0 [2] c3 f7 [2] df d8 }

  condition:
    any of them
}