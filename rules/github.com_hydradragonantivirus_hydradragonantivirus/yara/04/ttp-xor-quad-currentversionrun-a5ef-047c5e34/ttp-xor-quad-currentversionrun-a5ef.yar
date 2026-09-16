rule TTP_XOR_QUAD_CurrentVersionRun_a5ef {
  strings:
    $key_a5ef = { f6 80 [2] d2 8e [2] f9 a2 [2] d7 80 [2] c3 9b [2] cc 81 [2] d2 9c [2] d0 9d [2] cb 9b [2] d7 9c [2] cb b3 }

  condition:
    any of them
}