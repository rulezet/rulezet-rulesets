rule TTP_XOR_QUAD_CurrentVersionRun_974c {
  strings:
    $key_974c = { c4 23 [2] e0 2d [2] cb 01 [2] e5 23 [2] f1 38 [2] fe 22 [2] e0 3f [2] e2 3e [2] f9 38 [2] e5 3f [2] f9 10 }

  condition:
    any of them
}