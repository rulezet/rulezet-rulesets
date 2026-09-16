rule TTP_XOR_QUAD_CurrentVersionRun_a579 {
  strings:
    $key_a579 = { f6 16 [2] d2 18 [2] f9 34 [2] d7 16 [2] c3 0d [2] cc 17 [2] d2 0a [2] d0 0b [2] cb 0d [2] d7 0a [2] cb 25 }

  condition:
    any of them
}