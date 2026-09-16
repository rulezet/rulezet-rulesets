rule TTP_XOR_QUAD_CurrentVersionRun_97f3 {
  strings:
    $key_97f3 = { c4 9c [2] e0 92 [2] cb be [2] e5 9c [2] f1 87 [2] fe 9d [2] e0 80 [2] e2 81 [2] f9 87 [2] e5 80 [2] f9 af }

  condition:
    any of them
}