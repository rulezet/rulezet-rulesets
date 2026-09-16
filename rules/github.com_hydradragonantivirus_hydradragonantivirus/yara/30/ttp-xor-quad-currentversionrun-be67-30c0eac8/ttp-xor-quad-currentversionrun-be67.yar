rule TTP_XOR_QUAD_CurrentVersionRun_be67 {
  strings:
    $key_be67 = { ed 08 [2] c9 06 [2] e2 2a [2] cc 08 [2] d8 13 [2] d7 09 [2] c9 14 [2] cb 15 [2] d0 13 [2] cc 14 [2] d0 3b }

  condition:
    any of them
}