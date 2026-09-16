rule TTP_XOR_QUAD_CurrentVersionRun_a528 {
  strings:
    $key_a528 = { f6 47 [2] d2 49 [2] f9 65 [2] d7 47 [2] c3 5c [2] cc 46 [2] d2 5b [2] d0 5a [2] cb 5c [2] d7 5b [2] cb 74 }

  condition:
    any of them
}