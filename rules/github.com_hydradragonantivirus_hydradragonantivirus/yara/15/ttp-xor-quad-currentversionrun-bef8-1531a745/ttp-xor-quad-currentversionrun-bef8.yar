rule TTP_XOR_QUAD_CurrentVersionRun_bef8 {
  strings:
    $key_bef8 = { ed 97 [2] c9 99 [2] e2 b5 [2] cc 97 [2] d8 8c [2] d7 96 [2] c9 8b [2] cb 8a [2] d0 8c [2] cc 8b [2] d0 a4 }

  condition:
    any of them
}