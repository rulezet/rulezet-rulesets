rule TTP_XOR_QUAD_CurrentVersionRun_a516 {
  strings:
    $key_a516 = { f6 79 [2] d2 77 [2] f9 5b [2] d7 79 [2] c3 62 [2] cc 78 [2] d2 65 [2] d0 64 [2] cb 62 [2] d7 65 [2] cb 4a }

  condition:
    any of them
}