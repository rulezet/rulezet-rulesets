rule TTP_XOR_QUAD_CurrentVersionRun_a557 {
  strings:
    $key_a557 = { f6 38 [2] d2 36 [2] f9 1a [2] d7 38 [2] c3 23 [2] cc 39 [2] d2 24 [2] d0 25 [2] cb 23 [2] d7 24 [2] cb 0b }

  condition:
    any of them
}