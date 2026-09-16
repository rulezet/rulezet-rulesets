rule TTP_XOR_QUAD_CurrentVersionRun_a55b {
  strings:
    $key_a55b = { f6 34 [2] d2 3a [2] f9 16 [2] d7 34 [2] c3 2f [2] cc 35 [2] d2 28 [2] d0 29 [2] cb 2f [2] d7 28 [2] cb 07 }

  condition:
    any of them
}