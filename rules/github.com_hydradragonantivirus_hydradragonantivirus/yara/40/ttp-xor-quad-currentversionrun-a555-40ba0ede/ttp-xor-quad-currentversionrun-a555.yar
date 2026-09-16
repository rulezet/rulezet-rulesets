rule TTP_XOR_QUAD_CurrentVersionRun_a555 {
  strings:
    $key_a555 = { f6 3a [2] d2 34 [2] f9 18 [2] d7 3a [2] c3 21 [2] cc 3b [2] d2 26 [2] d0 27 [2] cb 21 [2] d7 26 [2] cb 09 }

  condition:
    any of them
}