rule TTP_XOR_QUAD_CurrentVersionRun_be0a {
  strings:
    $key_be0a = { ed 65 [2] c9 6b [2] e2 47 [2] cc 65 [2] d8 7e [2] d7 64 [2] c9 79 [2] cb 78 [2] d0 7e [2] cc 79 [2] d0 56 }

  condition:
    any of them
}