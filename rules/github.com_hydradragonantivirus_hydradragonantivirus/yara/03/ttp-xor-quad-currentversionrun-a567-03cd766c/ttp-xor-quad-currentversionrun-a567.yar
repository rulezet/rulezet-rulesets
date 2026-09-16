rule TTP_XOR_QUAD_CurrentVersionRun_a567 {
  strings:
    $key_a567 = { f6 08 [2] d2 06 [2] f9 2a [2] d7 08 [2] c3 13 [2] cc 09 [2] d2 14 [2] d0 15 [2] cb 13 [2] d7 14 [2] cb 3b }

  condition:
    any of them
}