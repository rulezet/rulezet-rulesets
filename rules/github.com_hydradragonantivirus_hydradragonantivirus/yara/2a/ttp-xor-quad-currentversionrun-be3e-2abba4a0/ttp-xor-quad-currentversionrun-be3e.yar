rule TTP_XOR_QUAD_CurrentVersionRun_be3e {
  strings:
    $key_be3e = { ed 51 [2] c9 5f [2] e2 73 [2] cc 51 [2] d8 4a [2] d7 50 [2] c9 4d [2] cb 4c [2] d0 4a [2] cc 4d [2] d0 62 }

  condition:
    any of them
}