rule TTP_XOR_QUAD_CurrentVersionRun_be7b {
  strings:
    $key_be7b = { ed 14 [2] c9 1a [2] e2 36 [2] cc 14 [2] d8 0f [2] d7 15 [2] c9 08 [2] cb 09 [2] d0 0f [2] cc 08 [2] d0 27 }

  condition:
    any of them
}