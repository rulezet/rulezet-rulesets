rule TTP_XOR_QUAD_CurrentVersionRun_a5e5 {
  strings:
    $key_a5e5 = { f6 8a [2] d2 84 [2] f9 a8 [2] d7 8a [2] c3 91 [2] cc 8b [2] d2 96 [2] d0 97 [2] cb 91 [2] d7 96 [2] cb b9 }

  condition:
    any of them
}