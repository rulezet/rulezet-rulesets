rule TTP_XOR_QUAD_CurrentVersionRun_b68a {
  strings:
    $key_b68a = { e5 e5 [2] c1 eb [2] ea c7 [2] c4 e5 [2] d0 fe [2] df e4 [2] c1 f9 [2] c3 f8 [2] d8 fe [2] c4 f9 [2] d8 d6 }

  condition:
    any of them
}