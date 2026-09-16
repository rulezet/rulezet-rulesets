rule TTP_XOR_QUAD_CurrentVersionRun_be47 {
  strings:
    $key_be47 = { ed 28 [2] c9 26 [2] e2 0a [2] cc 28 [2] d8 33 [2] d7 29 [2] c9 34 [2] cb 35 [2] d0 33 [2] cc 34 [2] d0 1b }

  condition:
    any of them
}