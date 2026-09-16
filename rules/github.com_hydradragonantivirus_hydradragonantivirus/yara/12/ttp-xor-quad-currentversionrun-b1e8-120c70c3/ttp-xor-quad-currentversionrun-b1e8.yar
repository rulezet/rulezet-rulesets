rule TTP_XOR_QUAD_CurrentVersionRun_b1e8 {
  strings:
    $key_b1e8 = { e2 87 [2] c6 89 [2] ed a5 [2] c3 87 [2] d7 9c [2] d8 86 [2] c6 9b [2] c4 9a [2] df 9c [2] c3 9b [2] df b4 }

  condition:
    any of them
}