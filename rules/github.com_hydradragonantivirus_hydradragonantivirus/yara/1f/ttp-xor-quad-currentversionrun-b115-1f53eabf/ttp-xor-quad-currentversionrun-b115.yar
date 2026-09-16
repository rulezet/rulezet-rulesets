rule TTP_XOR_QUAD_CurrentVersionRun_b115 {
  strings:
    $key_b115 = { e2 7a [2] c6 74 [2] ed 58 [2] c3 7a [2] d7 61 [2] d8 7b [2] c6 66 [2] c4 67 [2] df 61 [2] c3 66 [2] df 49 }

  condition:
    any of them
}