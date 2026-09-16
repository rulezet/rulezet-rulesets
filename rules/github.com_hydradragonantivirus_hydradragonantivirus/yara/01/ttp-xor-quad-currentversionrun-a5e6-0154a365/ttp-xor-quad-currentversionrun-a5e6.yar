rule TTP_XOR_QUAD_CurrentVersionRun_a5e6 {
  strings:
    $key_a5e6 = { f6 89 [2] d2 87 [2] f9 ab [2] d7 89 [2] c3 92 [2] cc 88 [2] d2 95 [2] d0 94 [2] cb 92 [2] d7 95 [2] cb ba }

  condition:
    any of them
}