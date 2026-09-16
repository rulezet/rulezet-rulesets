rule TTP_XOR_QUAD_CurrentVersionRun_be29 {
  strings:
    $key_be29 = { ed 46 [2] c9 48 [2] e2 64 [2] cc 46 [2] d8 5d [2] d7 47 [2] c9 5a [2] cb 5b [2] d0 5d [2] cc 5a [2] d0 75 }

  condition:
    any of them
}