rule TTP_XOR_QUAD_CurrentVersionRun_97d7 {
  strings:
    $key_97d7 = { c4 b8 [2] e0 b6 [2] cb 9a [2] e5 b8 [2] f1 a3 [2] fe b9 [2] e0 a4 [2] e2 a5 [2] f9 a3 [2] e5 a4 [2] f9 8b }

  condition:
    any of them
}