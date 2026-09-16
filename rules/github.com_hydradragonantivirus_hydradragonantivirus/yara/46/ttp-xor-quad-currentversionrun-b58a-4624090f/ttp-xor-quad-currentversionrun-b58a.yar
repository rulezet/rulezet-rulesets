rule TTP_XOR_QUAD_CurrentVersionRun_b58a {
  strings:
    $key_b58a = { e6 e5 [2] c2 eb [2] e9 c7 [2] c7 e5 [2] d3 fe [2] dc e4 [2] c2 f9 [2] c0 f8 [2] db fe [2] c7 f9 [2] db d6 }

  condition:
    any of them
}