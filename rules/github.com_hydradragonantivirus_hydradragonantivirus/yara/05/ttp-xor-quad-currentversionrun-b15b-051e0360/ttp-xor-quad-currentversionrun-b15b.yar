rule TTP_XOR_QUAD_CurrentVersionRun_b15b {
  strings:
    $key_b15b = { e2 34 [2] c6 3a [2] ed 16 [2] c3 34 [2] d7 2f [2] d8 35 [2] c6 28 [2] c4 29 [2] df 2f [2] c3 28 [2] df 07 }

  condition:
    any of them
}