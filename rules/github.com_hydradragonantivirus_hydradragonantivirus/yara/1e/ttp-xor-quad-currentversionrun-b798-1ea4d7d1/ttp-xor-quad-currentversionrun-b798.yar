rule TTP_XOR_QUAD_CurrentVersionRun_b798 {
  strings:
    $key_b798 = { e4 f7 [2] c0 f9 [2] eb d5 [2] c5 f7 [2] d1 ec [2] de f6 [2] c0 eb [2] c2 ea [2] d9 ec [2] c5 eb [2] d9 c4 }

  condition:
    any of them
}