rule TTP_XOR_QUAD_CurrentVersionRun_b48a {
  strings:
    $key_b48a = { e7 e5 [2] c3 eb [2] e8 c7 [2] c6 e5 [2] d2 fe [2] dd e4 [2] c3 f9 [2] c1 f8 [2] da fe [2] c6 f9 [2] da d6 }

  condition:
    any of them
}