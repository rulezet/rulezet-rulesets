rule TTP_XOR_QUAD_CurrentVersionRun_b172 {
  strings:
    $key_b172 = { e2 1d [2] c6 13 [2] ed 3f [2] c3 1d [2] d7 06 [2] d8 1c [2] c6 01 [2] c4 00 [2] df 06 [2] c3 01 [2] df 2e }

  condition:
    any of them
}