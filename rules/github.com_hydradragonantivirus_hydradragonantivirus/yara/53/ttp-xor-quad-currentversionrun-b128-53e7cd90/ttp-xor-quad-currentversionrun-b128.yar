rule TTP_XOR_QUAD_CurrentVersionRun_b128 {
  strings:
    $key_b128 = { e2 47 [2] c6 49 [2] ed 65 [2] c3 47 [2] d7 5c [2] d8 46 [2] c6 5b [2] c4 5a [2] df 5c [2] c3 5b [2] df 74 }

  condition:
    any of them
}