rule TTP_XOR_QUAD_CurrentVersionRun_b1e9 {
  strings:
    $key_b1e9 = { e2 86 [2] c6 88 [2] ed a4 [2] c3 86 [2] d7 9d [2] d8 87 [2] c6 9a [2] c4 9b [2] df 9d [2] c3 9a [2] df b5 }

  condition:
    any of them
}