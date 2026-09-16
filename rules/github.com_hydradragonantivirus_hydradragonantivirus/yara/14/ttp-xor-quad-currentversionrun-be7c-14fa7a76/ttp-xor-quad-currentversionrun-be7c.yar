rule TTP_XOR_QUAD_CurrentVersionRun_be7c {
  strings:
    $key_be7c = { ed 13 [2] c9 1d [2] e2 31 [2] cc 13 [2] d8 08 [2] d7 12 [2] c9 0f [2] cb 0e [2] d0 08 [2] cc 0f [2] d0 20 }

  condition:
    any of them
}