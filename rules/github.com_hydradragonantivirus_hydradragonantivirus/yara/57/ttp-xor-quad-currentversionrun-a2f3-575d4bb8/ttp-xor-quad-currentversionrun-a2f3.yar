rule TTP_XOR_QUAD_CurrentVersionRun_a2f3 {
  strings:
    $key_a2f3 = { f1 9c [2] d5 92 [2] fe be [2] d0 9c [2] c4 87 [2] cb 9d [2] d5 80 [2] d7 81 [2] cc 87 [2] d0 80 [2] cc af }

  condition:
    any of them
}