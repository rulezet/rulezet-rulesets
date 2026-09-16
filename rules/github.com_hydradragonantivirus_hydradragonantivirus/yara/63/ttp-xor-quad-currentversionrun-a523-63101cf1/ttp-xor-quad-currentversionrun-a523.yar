rule TTP_XOR_QUAD_CurrentVersionRun_a523 {
  strings:
    $key_a523 = { f6 4c [2] d2 42 [2] f9 6e [2] d7 4c [2] c3 57 [2] cc 4d [2] d2 50 [2] d0 51 [2] cb 57 [2] d7 50 [2] cb 7f }

  condition:
    any of them
}