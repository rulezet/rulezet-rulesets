rule TTP_XOR_QUAD_CurrentVersionRun_a503 {
  strings:
    $key_a503 = { f6 6c [2] d2 62 [2] f9 4e [2] d7 6c [2] c3 77 [2] cc 6d [2] d2 70 [2] d0 71 [2] cb 77 [2] d7 70 [2] cb 5f }

  condition:
    any of them
}