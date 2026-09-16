rule TTP_XOR_QUAD_CurrentVersionRun_a518 {
  strings:
    $key_a518 = { f6 77 [2] d2 79 [2] f9 55 [2] d7 77 [2] c3 6c [2] cc 76 [2] d2 6b [2] d0 6a [2] cb 6c [2] d7 6b [2] cb 44 }

  condition:
    any of them
}