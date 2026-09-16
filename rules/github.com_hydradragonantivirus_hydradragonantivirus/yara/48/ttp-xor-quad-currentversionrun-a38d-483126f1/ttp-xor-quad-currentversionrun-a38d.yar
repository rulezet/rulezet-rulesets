rule TTP_XOR_QUAD_CurrentVersionRun_a38d {
  strings:
    $key_a38d = { f0 e2 [2] d4 ec [2] ff c0 [2] d1 e2 [2] c5 f9 [2] ca e3 [2] d4 fe [2] d6 ff [2] cd f9 [2] d1 fe [2] cd d1 }

  condition:
    any of them
}