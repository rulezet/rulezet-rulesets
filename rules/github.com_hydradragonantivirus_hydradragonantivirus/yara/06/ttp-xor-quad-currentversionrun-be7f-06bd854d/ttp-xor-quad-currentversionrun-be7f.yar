rule TTP_XOR_QUAD_CurrentVersionRun_be7f {
  strings:
    $key_be7f = { ed 10 [2] c9 1e [2] e2 32 [2] cc 10 [2] d8 0b [2] d7 11 [2] c9 0c [2] cb 0d [2] d0 0b [2] cc 0c [2] d0 23 }

  condition:
    any of them
}