rule TTP_XOR_QUAD_CurrentVersionRun_be18 {
  strings:
    $key_be18 = { ed 77 [2] c9 79 [2] e2 55 [2] cc 77 [2] d8 6c [2] d7 76 [2] c9 6b [2] cb 6a [2] d0 6c [2] cc 6b [2] d0 44 }

  condition:
    any of them
}