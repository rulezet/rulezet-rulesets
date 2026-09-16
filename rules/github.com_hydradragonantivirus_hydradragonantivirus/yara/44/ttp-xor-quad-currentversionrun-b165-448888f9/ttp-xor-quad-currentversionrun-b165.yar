rule TTP_XOR_QUAD_CurrentVersionRun_b165 {
  strings:
    $key_b165 = { e2 0a [2] c6 04 [2] ed 28 [2] c3 0a [2] d7 11 [2] d8 0b [2] c6 16 [2] c4 17 [2] df 11 [2] c3 16 [2] df 39 }

  condition:
    any of them
}