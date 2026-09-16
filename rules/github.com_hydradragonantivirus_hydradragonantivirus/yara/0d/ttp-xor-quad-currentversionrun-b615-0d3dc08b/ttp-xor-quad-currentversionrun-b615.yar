rule TTP_XOR_QUAD_CurrentVersionRun_b615 {
  strings:
    $key_b615 = { e5 7a [2] c1 74 [2] ea 58 [2] c4 7a [2] d0 61 [2] df 7b [2] c1 66 [2] c3 67 [2] d8 61 [2] c4 66 [2] d8 49 }

  condition:
    any of them
}