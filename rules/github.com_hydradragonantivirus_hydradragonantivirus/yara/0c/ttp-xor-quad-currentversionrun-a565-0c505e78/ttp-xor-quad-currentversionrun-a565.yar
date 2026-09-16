rule TTP_XOR_QUAD_CurrentVersionRun_a565 {
  strings:
    $key_a565 = { f6 0a [2] d2 04 [2] f9 28 [2] d7 0a [2] c3 11 [2] cc 0b [2] d2 16 [2] d0 17 [2] cb 11 [2] d7 16 [2] cb 39 }

  condition:
    any of them
}