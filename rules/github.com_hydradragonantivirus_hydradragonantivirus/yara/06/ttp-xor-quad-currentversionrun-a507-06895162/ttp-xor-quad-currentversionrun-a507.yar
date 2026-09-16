rule TTP_XOR_QUAD_CurrentVersionRun_a507 {
  strings:
    $key_a507 = { f6 68 [2] d2 66 [2] f9 4a [2] d7 68 [2] c3 73 [2] cc 69 [2] d2 74 [2] d0 75 [2] cb 73 [2] d7 74 [2] cb 5b }

  condition:
    any of them
}