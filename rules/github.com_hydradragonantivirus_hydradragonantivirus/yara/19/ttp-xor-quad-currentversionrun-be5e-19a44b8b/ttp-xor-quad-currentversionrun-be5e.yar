rule TTP_XOR_QUAD_CurrentVersionRun_be5e {
  strings:
    $key_be5e = { ed 31 [2] c9 3f [2] e2 13 [2] cc 31 [2] d8 2a [2] d7 30 [2] c9 2d [2] cb 2c [2] d0 2a [2] cc 2d [2] d0 02 }

  condition:
    any of them
}