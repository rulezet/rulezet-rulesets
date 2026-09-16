rule TTP_XOR_QUAD_CurrentVersionRun_9752 {
  strings:
    $key_9752 = { c4 3d [2] e0 33 [2] cb 1f [2] e5 3d [2] f1 26 [2] fe 3c [2] e0 21 [2] e2 20 [2] f9 26 [2] e5 21 [2] f9 0e }

  condition:
    any of them
}