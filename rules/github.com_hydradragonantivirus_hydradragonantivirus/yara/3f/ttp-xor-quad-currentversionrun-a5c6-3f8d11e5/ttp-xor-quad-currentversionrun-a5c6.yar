rule TTP_XOR_QUAD_CurrentVersionRun_a5c6 {
  strings:
    $key_a5c6 = { f6 a9 [2] d2 a7 [2] f9 8b [2] d7 a9 [2] c3 b2 [2] cc a8 [2] d2 b5 [2] d0 b4 [2] cb b2 [2] d7 b5 [2] cb 9a }

  condition:
    any of them
}