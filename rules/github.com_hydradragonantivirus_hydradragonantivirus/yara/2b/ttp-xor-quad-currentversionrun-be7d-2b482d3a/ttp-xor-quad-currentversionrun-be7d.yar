rule TTP_XOR_QUAD_CurrentVersionRun_be7d {
  strings:
    $key_be7d = { ed 12 [2] c9 1c [2] e2 30 [2] cc 12 [2] d8 09 [2] d7 13 [2] c9 0e [2] cb 0f [2] d0 09 [2] cc 0e [2] d0 21 }

  condition:
    any of them
}