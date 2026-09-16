rule TTP_XOR_QUAD_CurrentVersionRun_b08b {
  strings:
    $key_b08b = { e3 e4 [2] c7 ea [2] ec c6 [2] c2 e4 [2] d6 ff [2] d9 e5 [2] c7 f8 [2] c5 f9 [2] de ff [2] c2 f8 [2] de d7 }

  condition:
    any of them
}