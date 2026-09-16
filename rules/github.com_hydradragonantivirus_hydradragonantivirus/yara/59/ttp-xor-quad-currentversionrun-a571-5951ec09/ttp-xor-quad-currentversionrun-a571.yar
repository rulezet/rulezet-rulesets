rule TTP_XOR_QUAD_CurrentVersionRun_a571 {
  strings:
    $key_a571 = { f6 1e [2] d2 10 [2] f9 3c [2] d7 1e [2] c3 05 [2] cc 1f [2] d2 02 [2] d0 03 [2] cb 05 [2] d7 02 [2] cb 2d }

  condition:
    any of them
}