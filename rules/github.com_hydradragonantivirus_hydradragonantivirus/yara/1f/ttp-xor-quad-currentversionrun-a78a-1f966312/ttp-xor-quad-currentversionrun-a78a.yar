rule TTP_XOR_QUAD_CurrentVersionRun_a78a {
  strings:
    $key_a78a = { f4 e5 [2] d0 eb [2] fb c7 [2] d5 e5 [2] c1 fe [2] ce e4 [2] d0 f9 [2] d2 f8 [2] c9 fe [2] d5 f9 [2] c9 d6 }

  condition:
    any of them
}