rule TTP_XOR_QUAD_CurrentVersionRun_b139 {
  strings:
    $key_b139 = { e2 56 [2] c6 58 [2] ed 74 [2] c3 56 [2] d7 4d [2] d8 57 [2] c6 4a [2] c4 4b [2] df 4d [2] c3 4a [2] df 65 }

  condition:
    any of them
}