rule TTP_XOR_QUAD_CurrentVersionRun_a544 {
  strings:
    $key_a544 = { f6 2b [2] d2 25 [2] f9 09 [2] d7 2b [2] c3 30 [2] cc 2a [2] d2 37 [2] d0 36 [2] cb 30 [2] d7 37 [2] cb 18 }

  condition:
    any of them
}