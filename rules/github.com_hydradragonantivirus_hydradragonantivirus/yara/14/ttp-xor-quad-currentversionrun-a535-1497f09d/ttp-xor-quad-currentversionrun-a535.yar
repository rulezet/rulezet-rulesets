rule TTP_XOR_QUAD_CurrentVersionRun_a535 {
  strings:
    $key_a535 = { f6 5a [2] d2 54 [2] f9 78 [2] d7 5a [2] c3 41 [2] cc 5b [2] d2 46 [2] d0 47 [2] cb 41 [2] d7 46 [2] cb 69 }

  condition:
    any of them
}