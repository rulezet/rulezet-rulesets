rule TTP_XOR_QUAD_CurrentVersionRun_bef5 {
  strings:
    $key_bef5 = { ed 9a [2] c9 94 [2] e2 b8 [2] cc 9a [2] d8 81 [2] d7 9b [2] c9 86 [2] cb 87 [2] d0 81 [2] cc 86 [2] d0 a9 }

  condition:
    any of them
}