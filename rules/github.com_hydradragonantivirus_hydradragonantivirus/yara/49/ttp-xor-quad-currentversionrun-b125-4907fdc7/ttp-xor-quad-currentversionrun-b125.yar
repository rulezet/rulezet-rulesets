rule TTP_XOR_QUAD_CurrentVersionRun_b125 {
  strings:
    $key_b125 = { e2 4a [2] c6 44 [2] ed 68 [2] c3 4a [2] d7 51 [2] d8 4b [2] c6 56 [2] c4 57 [2] df 51 [2] c3 56 [2] df 79 }

  condition:
    any of them
}