rule TTP_XOR_QUAD_CurrentVersionRun_a54b {
  strings:
    $key_a54b = { f6 24 [2] d2 2a [2] f9 06 [2] d7 24 [2] c3 3f [2] cc 25 [2] d2 38 [2] d0 39 [2] cb 3f [2] d7 38 [2] cb 17 }

  condition:
    any of them
}