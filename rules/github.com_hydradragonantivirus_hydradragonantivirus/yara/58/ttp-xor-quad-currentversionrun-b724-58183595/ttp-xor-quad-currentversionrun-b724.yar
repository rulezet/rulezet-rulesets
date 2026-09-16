rule TTP_XOR_QUAD_CurrentVersionRun_b724 {
  strings:
    $key_b724 = { e4 4b [2] c0 45 [2] eb 69 [2] c5 4b [2] d1 50 [2] de 4a [2] c0 57 [2] c2 56 [2] d9 50 [2] c5 57 [2] d9 78 }

  condition:
    any of them
}