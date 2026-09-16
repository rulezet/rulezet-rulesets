rule TTP_XOR_QUAD_CurrentVersionRun_be56 {
  strings:
    $key_be56 = { ed 39 [2] c9 37 [2] e2 1b [2] cc 39 [2] d8 22 [2] d7 38 [2] c9 25 [2] cb 24 [2] d0 22 [2] cc 25 [2] d0 0a }

  condition:
    any of them
}