rule TTP_XOR_QUAD_CurrentVersionRun_b70a {
  strings:
    $key_b70a = { e4 65 [2] c0 6b [2] eb 47 [2] c5 65 [2] d1 7e [2] de 64 [2] c0 79 [2] c2 78 [2] d9 7e [2] c5 79 [2] d9 56 }

  condition:
    any of them
}