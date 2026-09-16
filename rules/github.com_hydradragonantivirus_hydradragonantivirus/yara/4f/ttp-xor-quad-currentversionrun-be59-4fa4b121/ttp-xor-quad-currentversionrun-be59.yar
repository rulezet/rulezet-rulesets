rule TTP_XOR_QUAD_CurrentVersionRun_be59 {
  strings:
    $key_be59 = { ed 36 [2] c9 38 [2] e2 14 [2] cc 36 [2] d8 2d [2] d7 37 [2] c9 2a [2] cb 2b [2] d0 2d [2] cc 2a [2] d0 05 }

  condition:
    any of them
}