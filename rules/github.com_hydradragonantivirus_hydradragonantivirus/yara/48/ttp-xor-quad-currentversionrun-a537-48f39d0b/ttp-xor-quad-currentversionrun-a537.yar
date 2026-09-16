rule TTP_XOR_QUAD_CurrentVersionRun_a537 {
  strings:
    $key_a537 = { f6 58 [2] d2 56 [2] f9 7a [2] d7 58 [2] c3 43 [2] cc 59 [2] d2 44 [2] d0 45 [2] cb 43 [2] d7 44 [2] cb 6b }

  condition:
    any of them
}