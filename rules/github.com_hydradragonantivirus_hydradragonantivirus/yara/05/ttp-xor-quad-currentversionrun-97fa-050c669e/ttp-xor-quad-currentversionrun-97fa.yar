rule TTP_XOR_QUAD_CurrentVersionRun_97fa {
  strings:
    $key_97fa = { c4 95 [2] e0 9b [2] cb b7 [2] e5 95 [2] f1 8e [2] fe 94 [2] e0 89 [2] e2 88 [2] f9 8e [2] e5 89 [2] f9 a6 }

  condition:
    any of them
}