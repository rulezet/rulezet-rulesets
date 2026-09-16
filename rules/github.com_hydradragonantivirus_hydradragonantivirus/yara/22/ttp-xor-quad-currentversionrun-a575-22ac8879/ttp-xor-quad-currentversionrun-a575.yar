rule TTP_XOR_QUAD_CurrentVersionRun_a575 {
  strings:
    $key_a575 = { f6 1a [2] d2 14 [2] f9 38 [2] d7 1a [2] c3 01 [2] cc 1b [2] d2 06 [2] d0 07 [2] cb 01 [2] d7 06 [2] cb 29 }

  condition:
    any of them
}