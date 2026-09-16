rule TTP_XOR_QUAD_CurrentVersionRun_a5f9 {
  strings:
    $key_a5f9 = { f6 96 [2] d2 98 [2] f9 b4 [2] d7 96 [2] c3 8d [2] cc 97 [2] d2 8a [2] d0 8b [2] cb 8d [2] d7 8a [2] cb a5 }

  condition:
    any of them
}