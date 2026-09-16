rule TTP_XOR_QUAD_CurrentVersionRun_a509 {
  strings:
    $key_a509 = { f6 66 [2] d2 68 [2] f9 44 [2] d7 66 [2] c3 7d [2] cc 67 [2] d2 7a [2] d0 7b [2] cb 7d [2] d7 7a [2] cb 55 }

  condition:
    any of them
}