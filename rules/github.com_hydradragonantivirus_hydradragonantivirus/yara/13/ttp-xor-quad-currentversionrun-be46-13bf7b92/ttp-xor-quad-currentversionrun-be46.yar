rule TTP_XOR_QUAD_CurrentVersionRun_be46 {
  strings:
    $key_be46 = { ed 29 [2] c9 27 [2] e2 0b [2] cc 29 [2] d8 32 [2] d7 28 [2] c9 35 [2] cb 34 [2] d0 32 [2] cc 35 [2] d0 1a }

  condition:
    any of them
}