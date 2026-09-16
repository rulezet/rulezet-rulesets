rule TTP_XOR_QUAD_CurrentVersionRun_a541 {
  strings:
    $key_a541 = { f6 2e [2] d2 20 [2] f9 0c [2] d7 2e [2] c3 35 [2] cc 2f [2] d2 32 [2] d0 33 [2] cb 35 [2] d7 32 [2] cb 1d }

  condition:
    any of them
}