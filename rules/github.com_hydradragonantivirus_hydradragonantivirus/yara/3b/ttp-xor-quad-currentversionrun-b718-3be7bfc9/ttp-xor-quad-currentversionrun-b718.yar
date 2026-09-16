rule TTP_XOR_QUAD_CurrentVersionRun_b718 {
  strings:
    $key_b718 = { e4 77 [2] c0 79 [2] eb 55 [2] c5 77 [2] d1 6c [2] de 76 [2] c0 6b [2] c2 6a [2] d9 6c [2] c5 6b [2] d9 44 }

  condition:
    any of them
}