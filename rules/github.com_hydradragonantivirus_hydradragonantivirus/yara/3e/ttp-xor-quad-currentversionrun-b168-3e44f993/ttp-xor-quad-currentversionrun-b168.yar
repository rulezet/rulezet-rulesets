rule TTP_XOR_QUAD_CurrentVersionRun_b168 {
  strings:
    $key_b168 = { e2 07 [2] c6 09 [2] ed 25 [2] c3 07 [2] d7 1c [2] d8 06 [2] c6 1b [2] c4 1a [2] df 1c [2] c3 1b [2] df 34 }

  condition:
    any of them
}