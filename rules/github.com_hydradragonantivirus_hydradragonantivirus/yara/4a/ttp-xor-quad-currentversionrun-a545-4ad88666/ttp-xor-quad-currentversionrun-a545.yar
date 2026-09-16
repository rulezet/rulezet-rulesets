rule TTP_XOR_QUAD_CurrentVersionRun_a545 {
  strings:
    $key_a545 = { f6 2a [2] d2 24 [2] f9 08 [2] d7 2a [2] c3 31 [2] cc 2b [2] d2 36 [2] d0 37 [2] cb 31 [2] d7 36 [2] cb 19 }

  condition:
    any of them
}