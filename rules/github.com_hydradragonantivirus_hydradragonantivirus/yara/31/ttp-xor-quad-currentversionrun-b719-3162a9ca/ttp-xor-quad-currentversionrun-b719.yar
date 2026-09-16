rule TTP_XOR_QUAD_CurrentVersionRun_b719 {
  strings:
    $key_b719 = { e4 76 [2] c0 78 [2] eb 54 [2] c5 76 [2] d1 6d [2] de 77 [2] c0 6a [2] c2 6b [2] d9 6d [2] c5 6a [2] d9 45 }

  condition:
    any of them
}