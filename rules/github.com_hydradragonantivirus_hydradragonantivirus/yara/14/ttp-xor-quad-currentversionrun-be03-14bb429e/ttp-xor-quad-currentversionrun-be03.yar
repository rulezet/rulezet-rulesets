rule TTP_XOR_QUAD_CurrentVersionRun_be03 {
  strings:
    $key_be03 = { ed 6c [2] c9 62 [2] e2 4e [2] cc 6c [2] d8 77 [2] d7 6d [2] c9 70 [2] cb 71 [2] d0 77 [2] cc 70 [2] d0 5f }

  condition:
    any of them
}