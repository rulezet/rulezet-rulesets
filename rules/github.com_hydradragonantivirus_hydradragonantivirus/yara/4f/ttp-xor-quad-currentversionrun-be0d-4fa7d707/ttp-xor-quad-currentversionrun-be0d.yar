rule TTP_XOR_QUAD_CurrentVersionRun_be0d {
  strings:
    $key_be0d = { ed 62 [2] c9 6c [2] e2 40 [2] cc 62 [2] d8 79 [2] d7 63 [2] c9 7e [2] cb 7f [2] d0 79 [2] cc 7e [2] d0 51 }

  condition:
    any of them
}