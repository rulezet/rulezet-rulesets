rule TTP_XOR_QUAD_CurrentVersionRun_bee6 {
  strings:
    $key_bee6 = { ed 89 [2] c9 87 [2] e2 ab [2] cc 89 [2] d8 92 [2] d7 88 [2] c9 95 [2] cb 94 [2] d0 92 [2] cc 95 [2] d0 ba }

  condition:
    any of them
}