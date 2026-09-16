rule TTP_XOR_QUAD_CurrentVersionRun_b704 {
  strings:
    $key_b704 = { e4 6b [2] c0 65 [2] eb 49 [2] c5 6b [2] d1 70 [2] de 6a [2] c0 77 [2] c2 76 [2] d9 70 [2] c5 77 [2] d9 58 }

  condition:
    any of them
}