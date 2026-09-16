rule TTP_XOR_QUAD_CurrentVersionRun_b708 {
  strings:
    $key_b708 = { e4 67 [2] c0 69 [2] eb 45 [2] c5 67 [2] d1 7c [2] de 66 [2] c0 7b [2] c2 7a [2] d9 7c [2] c5 7b [2] d9 54 }

  condition:
    any of them
}