rule TTP_XOR_QUAD_CurrentVersionRun_a38a {
  strings:
    $key_a38a = { f0 e5 [2] d4 eb [2] ff c7 [2] d1 e5 [2] c5 fe [2] ca e4 [2] d4 f9 [2] d6 f8 [2] cd fe [2] d1 f9 [2] cd d6 }

  condition:
    any of them
}