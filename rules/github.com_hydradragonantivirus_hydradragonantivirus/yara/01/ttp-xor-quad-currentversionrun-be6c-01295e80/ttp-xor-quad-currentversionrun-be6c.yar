rule TTP_XOR_QUAD_CurrentVersionRun_be6c {
  strings:
    $key_be6c = { ed 03 [2] c9 0d [2] e2 21 [2] cc 03 [2] d8 18 [2] d7 02 [2] c9 1f [2] cb 1e [2] d0 18 [2] cc 1f [2] d0 30 }

  condition:
    any of them
}