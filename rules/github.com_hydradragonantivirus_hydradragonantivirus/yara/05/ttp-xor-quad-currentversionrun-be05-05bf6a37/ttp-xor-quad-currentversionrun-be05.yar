rule TTP_XOR_QUAD_CurrentVersionRun_be05 {
  strings:
    $key_be05 = { ed 6a [2] c9 64 [2] e2 48 [2] cc 6a [2] d8 71 [2] d7 6b [2] c9 76 [2] cb 77 [2] d0 71 [2] cc 76 [2] d0 59 }

  condition:
    any of them
}