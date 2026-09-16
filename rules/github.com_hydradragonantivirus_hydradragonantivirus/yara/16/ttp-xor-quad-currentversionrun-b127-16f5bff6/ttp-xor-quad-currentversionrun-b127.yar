rule TTP_XOR_QUAD_CurrentVersionRun_b127 {
  strings:
    $key_b127 = { e2 48 [2] c6 46 [2] ed 6a [2] c3 48 [2] d7 53 [2] d8 49 [2] c6 54 [2] c4 55 [2] df 53 [2] c3 54 [2] df 7b }

  condition:
    any of them
}