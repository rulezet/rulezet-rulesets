rule TTP_XOR_QUAD_CurrentVersionRun_a5e4 {
  strings:
    $key_a5e4 = { f6 8b [2] d2 85 [2] f9 a9 [2] d7 8b [2] c3 90 [2] cc 8a [2] d2 97 [2] d0 96 [2] cb 90 [2] d7 97 [2] cb b8 }

  condition:
    any of them
}