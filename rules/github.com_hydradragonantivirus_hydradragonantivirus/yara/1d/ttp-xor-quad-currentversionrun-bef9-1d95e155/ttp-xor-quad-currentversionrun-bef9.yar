rule TTP_XOR_QUAD_CurrentVersionRun_bef9 {
  strings:
    $key_bef9 = { ed 96 [2] c9 98 [2] e2 b4 [2] cc 96 [2] d8 8d [2] d7 97 [2] c9 8a [2] cb 8b [2] d0 8d [2] cc 8a [2] d0 a5 }

  condition:
    any of them
}