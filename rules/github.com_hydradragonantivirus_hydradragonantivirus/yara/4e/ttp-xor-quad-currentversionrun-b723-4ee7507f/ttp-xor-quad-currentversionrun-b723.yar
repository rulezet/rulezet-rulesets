rule TTP_XOR_QUAD_CurrentVersionRun_b723 {
  strings:
    $key_b723 = { e4 4c [2] c0 42 [2] eb 6e [2] c5 4c [2] d1 57 [2] de 4d [2] c0 50 [2] c2 51 [2] d9 57 [2] c5 50 [2] d9 7f }

  condition:
    any of them
}