rule TTP_XOR_QUAD_CurrentVersionRun_a5ee {
  strings:
    $key_a5ee = { f6 81 [2] d2 8f [2] f9 a3 [2] d7 81 [2] c3 9a [2] cc 80 [2] d2 9d [2] d0 9c [2] cb 9a [2] d7 9d [2] cb b2 }

  condition:
    any of them
}