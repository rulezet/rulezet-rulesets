rule TTP_XOR_QUAD_CurrentVersionRun_be5a {
  strings:
    $key_be5a = { ed 35 [2] c9 3b [2] e2 17 [2] cc 35 [2] d8 2e [2] d7 34 [2] c9 29 [2] cb 28 [2] d0 2e [2] cc 29 [2] d0 06 }

  condition:
    any of them
}