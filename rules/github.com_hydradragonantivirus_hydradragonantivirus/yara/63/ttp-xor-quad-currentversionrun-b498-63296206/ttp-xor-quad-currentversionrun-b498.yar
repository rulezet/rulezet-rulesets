rule TTP_XOR_QUAD_CurrentVersionRun_b498 {
  strings:
    $key_b498 = { e7 f7 [2] c3 f9 [2] e8 d5 [2] c6 f7 [2] d2 ec [2] dd f6 [2] c3 eb [2] c1 ea [2] da ec [2] c6 eb [2] da c4 }

  condition:
    any of them
}