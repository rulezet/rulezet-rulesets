rule TTP_XOR_QUAD_CurrentVersionRun_b18d {
  strings:
    $key_b18d = { e2 e2 [2] c6 ec [2] ed c0 [2] c3 e2 [2] d7 f9 [2] d8 e3 [2] c6 fe [2] c4 ff [2] df f9 [2] c3 fe [2] df d1 }

  condition:
    any of them
}