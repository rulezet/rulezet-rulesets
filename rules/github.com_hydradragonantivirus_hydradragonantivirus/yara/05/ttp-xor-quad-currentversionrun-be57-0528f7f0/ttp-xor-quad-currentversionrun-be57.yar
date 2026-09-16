rule TTP_XOR_QUAD_CurrentVersionRun_be57 {
  strings:
    $key_be57 = { ed 38 [2] c9 36 [2] e2 1a [2] cc 38 [2] d8 23 [2] d7 39 [2] c9 24 [2] cb 25 [2] d0 23 [2] cc 24 [2] d0 0b }

  condition:
    any of them
}