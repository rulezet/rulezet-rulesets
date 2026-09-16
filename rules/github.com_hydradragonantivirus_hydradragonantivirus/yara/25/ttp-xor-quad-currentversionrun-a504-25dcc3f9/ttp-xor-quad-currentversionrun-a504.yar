rule TTP_XOR_QUAD_CurrentVersionRun_a504 {
  strings:
    $key_a504 = { f6 6b [2] d2 65 [2] f9 49 [2] d7 6b [2] c3 70 [2] cc 6a [2] d2 77 [2] d0 76 [2] cb 70 [2] d7 77 [2] cb 58 }

  condition:
    any of them
}