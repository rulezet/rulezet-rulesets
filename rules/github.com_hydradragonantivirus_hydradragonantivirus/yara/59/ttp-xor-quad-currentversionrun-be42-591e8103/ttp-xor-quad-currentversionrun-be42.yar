rule TTP_XOR_QUAD_CurrentVersionRun_be42 {
  strings:
    $key_be42 = { ed 2d [2] c9 23 [2] e2 0f [2] cc 2d [2] d8 36 [2] d7 2c [2] c9 31 [2] cb 30 [2] d0 36 [2] cc 31 [2] d0 1e }

  condition:
    any of them
}