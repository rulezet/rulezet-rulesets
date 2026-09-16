rule TTP_XOR_QUAD_CurrentVersionRun_be09 {
  strings:
    $key_be09 = { ed 66 [2] c9 68 [2] e2 44 [2] cc 66 [2] d8 7d [2] d7 67 [2] c9 7a [2] cb 7b [2] d0 7d [2] cc 7a [2] d0 55 }

  condition:
    any of them
}