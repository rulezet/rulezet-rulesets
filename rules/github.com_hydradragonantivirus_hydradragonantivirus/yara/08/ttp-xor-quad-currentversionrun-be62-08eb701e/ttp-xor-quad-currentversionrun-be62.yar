rule TTP_XOR_QUAD_CurrentVersionRun_be62 {
  strings:
    $key_be62 = { ed 0d [2] c9 03 [2] e2 2f [2] cc 0d [2] d8 16 [2] d7 0c [2] c9 11 [2] cb 10 [2] d0 16 [2] cc 11 [2] d0 3e }

  condition:
    any of them
}