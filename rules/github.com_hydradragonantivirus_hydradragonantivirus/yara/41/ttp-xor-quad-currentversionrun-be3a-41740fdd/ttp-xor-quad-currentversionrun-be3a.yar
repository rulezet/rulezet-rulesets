rule TTP_XOR_QUAD_CurrentVersionRun_be3a {
  strings:
    $key_be3a = { ed 55 [2] c9 5b [2] e2 77 [2] cc 55 [2] d8 4e [2] d7 54 [2] c9 49 [2] cb 48 [2] d0 4e [2] cc 49 [2] d0 66 }

  condition:
    any of them
}