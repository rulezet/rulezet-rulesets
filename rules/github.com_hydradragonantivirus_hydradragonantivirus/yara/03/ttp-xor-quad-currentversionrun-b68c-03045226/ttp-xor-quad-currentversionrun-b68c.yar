rule TTP_XOR_QUAD_CurrentVersionRun_b68c {
  strings:
    $key_b68c = { e5 e3 [2] c1 ed [2] ea c1 [2] c4 e3 [2] d0 f8 [2] df e2 [2] c1 ff [2] c3 fe [2] d8 f8 [2] c4 ff [2] d8 d0 }

  condition:
    any of them
}