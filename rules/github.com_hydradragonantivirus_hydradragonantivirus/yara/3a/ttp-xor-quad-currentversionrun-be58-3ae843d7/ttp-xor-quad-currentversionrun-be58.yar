rule TTP_XOR_QUAD_CurrentVersionRun_be58 {
  strings:
    $key_be58 = { ed 37 [2] c9 39 [2] e2 15 [2] cc 37 [2] d8 2c [2] d7 36 [2] c9 2b [2] cb 2a [2] d0 2c [2] cc 2b [2] d0 04 }

  condition:
    any of them
}