rule TTP_XOR_QUAD_CurrentVersionRun_97e4 {
  strings:
    $key_97e4 = { c4 8b [2] e0 85 [2] cb a9 [2] e5 8b [2] f1 90 [2] fe 8a [2] e0 97 [2] e2 96 [2] f9 90 [2] e5 97 [2] f9 b8 }

  condition:
    any of them
}