rule TTP_XOR_QUAD_CurrentVersionRun_a525 {
  strings:
    $key_a525 = { f6 4a [2] d2 44 [2] f9 68 [2] d7 4a [2] c3 51 [2] cc 4b [2] d2 56 [2] d0 57 [2] cb 51 [2] d7 56 [2] cb 79 }

  condition:
    any of them
}