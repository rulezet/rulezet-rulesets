rule TTP_XOR_QUAD_CurrentVersionRun_97d1 {
  strings:
    $key_97d1 = { c4 be [2] e0 b0 [2] cb 9c [2] e5 be [2] f1 a5 [2] fe bf [2] e0 a2 [2] e2 a3 [2] f9 a5 [2] e5 a2 [2] f9 8d }

  condition:
    any of them
}