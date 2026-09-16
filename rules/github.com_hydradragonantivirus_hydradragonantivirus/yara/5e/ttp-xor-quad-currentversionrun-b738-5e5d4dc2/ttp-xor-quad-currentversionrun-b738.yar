rule TTP_XOR_QUAD_CurrentVersionRun_b738 {
  strings:
    $key_b738 = { e4 57 [2] c0 59 [2] eb 75 [2] c5 57 [2] d1 4c [2] de 56 [2] c0 4b [2] c2 4a [2] d9 4c [2] c5 4b [2] d9 64 }

  condition:
    any of them
}