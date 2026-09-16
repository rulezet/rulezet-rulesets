rule TTP_XOR_QUAD_CurrentVersionRun_b6f4 {
  strings:
    $key_b6f4 = { e5 9b [2] c1 95 [2] ea b9 [2] c4 9b [2] d0 80 [2] df 9a [2] c1 87 [2] c3 86 [2] d8 80 [2] c4 87 [2] d8 a8 }

  condition:
    any of them
}