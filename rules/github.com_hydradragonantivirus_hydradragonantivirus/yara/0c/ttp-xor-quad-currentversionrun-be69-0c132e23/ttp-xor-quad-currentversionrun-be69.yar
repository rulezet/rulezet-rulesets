rule TTP_XOR_QUAD_CurrentVersionRun_be69 {
  strings:
    $key_be69 = { ed 06 [2] c9 08 [2] e2 24 [2] cc 06 [2] d8 1d [2] d7 07 [2] c9 1a [2] cb 1b [2] d0 1d [2] cc 1a [2] d0 35 }

  condition:
    any of them
}