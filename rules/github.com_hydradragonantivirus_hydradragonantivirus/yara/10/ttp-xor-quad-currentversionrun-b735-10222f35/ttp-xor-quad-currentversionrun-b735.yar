rule TTP_XOR_QUAD_CurrentVersionRun_b735 {
  strings:
    $key_b735 = { e4 5a [2] c0 54 [2] eb 78 [2] c5 5a [2] d1 41 [2] de 5b [2] c0 46 [2] c2 47 [2] d9 41 [2] c5 46 [2] d9 69 }

  condition:
    any of them
}