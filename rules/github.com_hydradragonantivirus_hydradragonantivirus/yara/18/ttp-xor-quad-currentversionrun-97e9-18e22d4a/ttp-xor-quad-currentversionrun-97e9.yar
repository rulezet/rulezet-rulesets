rule TTP_XOR_QUAD_CurrentVersionRun_97e9 {
  strings:
    $key_97e9 = { c4 86 [2] e0 88 [2] cb a4 [2] e5 86 [2] f1 9d [2] fe 87 [2] e0 9a [2] e2 9b [2] f9 9d [2] e5 9a [2] f9 b5 }

  condition:
    any of them
}