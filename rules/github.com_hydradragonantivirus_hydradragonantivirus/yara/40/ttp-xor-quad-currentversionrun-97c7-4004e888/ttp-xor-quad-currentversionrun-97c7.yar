rule TTP_XOR_QUAD_CurrentVersionRun_97c7 {
  strings:
    $key_97c7 = { c4 a8 [2] e0 a6 [2] cb 8a [2] e5 a8 [2] f1 b3 [2] fe a9 [2] e0 b4 [2] e2 b5 [2] f9 b3 [2] e5 b4 [2] f9 9b }

  condition:
    any of them
}