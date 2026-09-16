rule TTP_XOR_QUAD_CurrentVersionRun_be7a {
  strings:
    $key_be7a = { ed 15 [2] c9 1b [2] e2 37 [2] cc 15 [2] d8 0e [2] d7 14 [2] c9 09 [2] cb 08 [2] d0 0e [2] cc 09 [2] d0 26 }

  condition:
    any of them
}