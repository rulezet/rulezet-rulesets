rule TTP_XOR_QUAD_CurrentVersionRun_a54c {
  strings:
    $key_a54c = { f6 23 [2] d2 2d [2] f9 01 [2] d7 23 [2] c3 38 [2] cc 22 [2] d2 3f [2] d0 3e [2] cb 38 [2] d7 3f [2] cb 10 }

  condition:
    any of them
}