rule TTP_XOR_QUAD_CurrentVersionRun_be75 {
  strings:
    $key_be75 = { ed 1a [2] c9 14 [2] e2 38 [2] cc 1a [2] d8 01 [2] d7 1b [2] c9 06 [2] cb 07 [2] d0 01 [2] cc 06 [2] d0 29 }

  condition:
    any of them
}