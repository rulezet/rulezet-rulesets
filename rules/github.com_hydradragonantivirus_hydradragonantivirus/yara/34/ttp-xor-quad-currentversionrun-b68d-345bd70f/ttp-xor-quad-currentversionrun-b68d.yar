rule TTP_XOR_QUAD_CurrentVersionRun_b68d {
  strings:
    $key_b68d = { e5 e2 [2] c1 ec [2] ea c0 [2] c4 e2 [2] d0 f9 [2] df e3 [2] c1 fe [2] c3 ff [2] d8 f9 [2] c4 fe [2] d8 d1 }

  condition:
    any of them
}