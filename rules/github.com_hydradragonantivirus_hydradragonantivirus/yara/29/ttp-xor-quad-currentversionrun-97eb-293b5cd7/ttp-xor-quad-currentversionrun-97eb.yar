rule TTP_XOR_QUAD_CurrentVersionRun_97eb {
  strings:
    $key_97eb = { c4 84 [2] e0 8a [2] cb a6 [2] e5 84 [2] f1 9f [2] fe 85 [2] e0 98 [2] e2 99 [2] f9 9f [2] e5 98 [2] f9 b7 }

  condition:
    any of them
}