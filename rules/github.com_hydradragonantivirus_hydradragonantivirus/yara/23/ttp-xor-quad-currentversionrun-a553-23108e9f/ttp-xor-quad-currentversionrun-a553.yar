rule TTP_XOR_QUAD_CurrentVersionRun_a553 {
  strings:
    $key_a553 = { f6 3c [2] d2 32 [2] f9 1e [2] d7 3c [2] c3 27 [2] cc 3d [2] d2 20 [2] d0 21 [2] cb 27 [2] d7 20 [2] cb 0f }

  condition:
    any of them
}