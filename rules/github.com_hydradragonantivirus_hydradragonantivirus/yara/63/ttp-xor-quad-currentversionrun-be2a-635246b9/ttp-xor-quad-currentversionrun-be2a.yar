rule TTP_XOR_QUAD_CurrentVersionRun_be2a {
  strings:
    $key_be2a = { ed 45 [2] c9 4b [2] e2 67 [2] cc 45 [2] d8 5e [2] d7 44 [2] c9 59 [2] cb 58 [2] d0 5e [2] cc 59 [2] d0 76 }

  condition:
    any of them
}