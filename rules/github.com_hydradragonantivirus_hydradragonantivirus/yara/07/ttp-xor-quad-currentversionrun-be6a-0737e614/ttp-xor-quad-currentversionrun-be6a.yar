rule TTP_XOR_QUAD_CurrentVersionRun_be6a {
  strings:
    $key_be6a = { ed 05 [2] c9 0b [2] e2 27 [2] cc 05 [2] d8 1e [2] d7 04 [2] c9 19 [2] cb 18 [2] d0 1e [2] cc 19 [2] d0 36 }

  condition:
    any of them
}