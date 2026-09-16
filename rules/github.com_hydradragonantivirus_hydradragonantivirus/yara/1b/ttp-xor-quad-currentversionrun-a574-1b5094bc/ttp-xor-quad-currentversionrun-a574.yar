rule TTP_XOR_QUAD_CurrentVersionRun_a574 {
  strings:
    $key_a574 = { f6 1b [2] d2 15 [2] f9 39 [2] d7 1b [2] c3 00 [2] cc 1a [2] d2 07 [2] d0 06 [2] cb 00 [2] d7 07 [2] cb 28 }

  condition:
    any of them
}