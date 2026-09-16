rule TTP_XOR_QUAD_CurrentVersionRun_b748 {
  strings:
    $key_b748 = { e4 27 [2] c0 29 [2] eb 05 [2] c5 27 [2] d1 3c [2] de 26 [2] c0 3b [2] c2 3a [2] d9 3c [2] c5 3b [2] d9 14 }

  condition:
    any of them
}