rule TTP_XOR_QUAD_CurrentVersionRun_a38b {
  strings:
    $key_a38b = { f0 e4 [2] d4 ea [2] ff c6 [2] d1 e4 [2] c5 ff [2] ca e5 [2] d4 f8 [2] d6 f9 [2] cd ff [2] d1 f8 [2] cd d7 }

  condition:
    any of them
}