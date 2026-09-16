rule TTP_XOR_QUAD_CurrentVersionRun_be15 {
  strings:
    $key_be15 = { ed 7a [2] c9 74 [2] e2 58 [2] cc 7a [2] d8 61 [2] d7 7b [2] c9 66 [2] cb 67 [2] d0 61 [2] cc 66 [2] d0 49 }

  condition:
    any of them
}