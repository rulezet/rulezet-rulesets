rule TTP_XOR_QUAD_CurrentVersionRun_b698 {
  strings:
    $key_b698 = { e5 f7 [2] c1 f9 [2] ea d5 [2] c4 f7 [2] d0 ec [2] df f6 [2] c1 eb [2] c3 ea [2] d8 ec [2] c4 eb [2] d8 c4 }

  condition:
    any of them
}