rule TTP_XOR_QUAD_CurrentVersionRun_b18a {
  strings:
    $key_b18a = { e2 e5 [2] c6 eb [2] ed c7 [2] c3 e5 [2] d7 fe [2] d8 e4 [2] c6 f9 [2] c4 f8 [2] df fe [2] c3 f9 [2] df d6 }

  condition:
    any of them
}