rule TTP_XOR_QUAD_CurrentVersionRun_be5b {
  strings:
    $key_be5b = { ed 34 [2] c9 3a [2] e2 16 [2] cc 34 [2] d8 2f [2] d7 35 [2] c9 28 [2] cb 29 [2] d0 2f [2] cc 28 [2] d0 07 }

  condition:
    any of them
}