rule TTP_XOR_QUAD_CurrentVersionRun_97f5 {
  strings:
    $key_97f5 = { c4 9a [2] e0 94 [2] cb b8 [2] e5 9a [2] f1 81 [2] fe 9b [2] e0 86 [2] e2 87 [2] f9 81 [2] e5 86 [2] f9 a9 }

  condition:
    any of them
}