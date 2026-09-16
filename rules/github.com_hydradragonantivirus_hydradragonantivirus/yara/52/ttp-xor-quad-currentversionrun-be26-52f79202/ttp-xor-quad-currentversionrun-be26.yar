rule TTP_XOR_QUAD_CurrentVersionRun_be26 {
  strings:
    $key_be26 = { ed 49 [2] c9 47 [2] e2 6b [2] cc 49 [2] d8 52 [2] d7 48 [2] c9 55 [2] cb 54 [2] d0 52 [2] cc 55 [2] d0 7a }

  condition:
    any of them
}