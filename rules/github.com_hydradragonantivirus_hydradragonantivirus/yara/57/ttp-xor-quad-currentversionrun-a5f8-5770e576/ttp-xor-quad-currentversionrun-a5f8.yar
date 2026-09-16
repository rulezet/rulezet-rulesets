rule TTP_XOR_QUAD_CurrentVersionRun_a5f8 {
  strings:
    $key_a5f8 = { f6 97 [2] d2 99 [2] f9 b5 [2] d7 97 [2] c3 8c [2] cc 96 [2] d2 8b [2] d0 8a [2] cb 8c [2] d7 8b [2] cb a4 }

  condition:
    any of them
}