rule TTP_XOR_QUAD_CurrentVersionRun_a5f3 {
  strings:
    $key_a5f3 = { f6 9c [2] d2 92 [2] f9 be [2] d7 9c [2] c3 87 [2] cc 9d [2] d2 80 [2] d0 81 [2] cb 87 [2] d7 80 [2] cb af }

  condition:
    any of them
}