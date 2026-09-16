rule TTP_XOR_QUAD_CurrentVersionRun_be37 {
  strings:
    $key_be37 = { ed 58 [2] c9 56 [2] e2 7a [2] cc 58 [2] d8 43 [2] d7 59 [2] c9 44 [2] cb 45 [2] d0 43 [2] cc 44 [2] d0 6b }

  condition:
    any of them
}