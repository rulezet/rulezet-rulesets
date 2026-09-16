rule TTP_XOR_QUAD_CurrentVersionRun_b70f {
  strings:
    $key_b70f = { e4 60 [2] c0 6e [2] eb 42 [2] c5 60 [2] d1 7b [2] de 61 [2] c0 7c [2] c2 7d [2] d9 7b [2] c5 7c [2] d9 53 }

  condition:
    any of them
}