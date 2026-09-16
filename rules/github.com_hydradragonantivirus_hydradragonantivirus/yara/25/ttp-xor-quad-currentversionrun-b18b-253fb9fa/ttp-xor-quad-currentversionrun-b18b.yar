rule TTP_XOR_QUAD_CurrentVersionRun_b18b {
  strings:
    $key_b18b = { e2 e4 [2] c6 ea [2] ed c6 [2] c3 e4 [2] d7 ff [2] d8 e5 [2] c6 f8 [2] c4 f9 [2] df ff [2] c3 f8 [2] df d7 }

  condition:
    any of them
}