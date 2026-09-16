rule TTP_XOR_QUAD_CurrentVersionRun_97ee {
  strings:
    $key_97ee = { c4 81 [2] e0 8f [2] cb a3 [2] e5 81 [2] f1 9a [2] fe 80 [2] e0 9d [2] e2 9c [2] f9 9a [2] e5 9d [2] f9 b2 }

  condition:
    any of them
}