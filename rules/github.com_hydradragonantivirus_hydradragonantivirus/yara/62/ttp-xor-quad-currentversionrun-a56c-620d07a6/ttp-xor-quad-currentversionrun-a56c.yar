rule TTP_XOR_QUAD_CurrentVersionRun_a56c {
  strings:
    $key_a56c = { f6 03 [2] d2 0d [2] f9 21 [2] d7 03 [2] c3 18 [2] cc 02 [2] d2 1f [2] d0 1e [2] cb 18 [2] d7 1f [2] cb 30 }

  condition:
    any of them
}