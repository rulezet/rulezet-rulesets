rule TTP_XOR_QUAD_CurrentVersionRun_a556 {
  strings:
    $key_a556 = { f6 39 [2] d2 37 [2] f9 1b [2] d7 39 [2] c3 22 [2] cc 38 [2] d2 25 [2] d0 24 [2] cb 22 [2] d7 25 [2] cb 0a }

  condition:
    any of them
}