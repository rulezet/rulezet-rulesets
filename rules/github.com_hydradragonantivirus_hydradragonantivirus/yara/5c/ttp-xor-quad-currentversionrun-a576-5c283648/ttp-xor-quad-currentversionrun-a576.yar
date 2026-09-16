rule TTP_XOR_QUAD_CurrentVersionRun_a576 {
  strings:
    $key_a576 = { f6 19 [2] d2 17 [2] f9 3b [2] d7 19 [2] c3 02 [2] cc 18 [2] d2 05 [2] d0 04 [2] cb 02 [2] d7 05 [2] cb 2a }

  condition:
    any of them
}