rule TTP_XOR_QUAD_CurrentVersionRun_be1d {
  strings:
    $key_be1d = { ed 72 [2] c9 7c [2] e2 50 [2] cc 72 [2] d8 69 [2] d7 73 [2] c9 6e [2] cb 6f [2] d0 69 [2] cc 6e [2] d0 41 }

  condition:
    any of them
}