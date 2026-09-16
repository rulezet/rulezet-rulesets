rule TTP_XOR_QUAD_CurrentVersionRun_b169 {
  strings:
    $key_b169 = { e2 06 [2] c6 08 [2] ed 24 [2] c3 06 [2] d7 1d [2] d8 07 [2] c6 1a [2] c4 1b [2] df 1d [2] c3 1a [2] df 35 }

  condition:
    any of them
}