rule TTP_XOR_QUAD_CurrentVersionRun_b104 {
  strings:
    $key_b104 = { e2 6b [2] c6 65 [2] ed 49 [2] c3 6b [2] d7 70 [2] d8 6a [2] c6 77 [2] c4 76 [2] df 70 [2] c3 77 [2] df 58 }

  condition:
    any of them
}