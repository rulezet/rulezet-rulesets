rule TTP_XOR_QUAD_CurrentVersionRun_be6f {
  strings:
    $key_be6f = { ed 00 [2] c9 0e [2] e2 22 [2] cc 00 [2] d8 1b [2] d7 01 [2] c9 1c [2] cb 1d [2] d0 1b [2] cc 1c [2] d0 33 }

  condition:
    any of them
}