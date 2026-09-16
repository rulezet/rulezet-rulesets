rule TTP_XOR_QUAD_CurrentVersionRun_be40 {
  strings:
    $key_be40 = { ed 2f [2] c9 21 [2] e2 0d [2] cc 2f [2] d8 34 [2] d7 2e [2] c9 33 [2] cb 32 [2] d0 34 [2] cc 33 [2] d0 1c }

  condition:
    any of them
}