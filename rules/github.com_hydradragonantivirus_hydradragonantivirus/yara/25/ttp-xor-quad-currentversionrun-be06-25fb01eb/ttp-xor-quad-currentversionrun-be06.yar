rule TTP_XOR_QUAD_CurrentVersionRun_be06 {
  strings:
    $key_be06 = { ed 69 [2] c9 67 [2] e2 4b [2] cc 69 [2] d8 72 [2] d7 68 [2] c9 75 [2] cb 74 [2] d0 72 [2] cc 75 [2] d0 5a }

  condition:
    any of them
}