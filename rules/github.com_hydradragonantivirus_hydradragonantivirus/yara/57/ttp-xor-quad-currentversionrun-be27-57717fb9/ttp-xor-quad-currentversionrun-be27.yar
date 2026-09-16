rule TTP_XOR_QUAD_CurrentVersionRun_be27 {
  strings:
    $key_be27 = { ed 48 [2] c9 46 [2] e2 6a [2] cc 48 [2] d8 53 [2] d7 49 [2] c9 54 [2] cb 55 [2] d0 53 [2] cc 54 [2] d0 7b }

  condition:
    any of them
}