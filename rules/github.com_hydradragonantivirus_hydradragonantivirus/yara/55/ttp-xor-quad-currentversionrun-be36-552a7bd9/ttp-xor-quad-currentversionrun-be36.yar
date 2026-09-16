rule TTP_XOR_QUAD_CurrentVersionRun_be36 {
  strings:
    $key_be36 = { ed 59 [2] c9 57 [2] e2 7b [2] cc 59 [2] d8 42 [2] d7 58 [2] c9 45 [2] cb 44 [2] d0 42 [2] cc 45 [2] d0 6a }

  condition:
    any of them
}