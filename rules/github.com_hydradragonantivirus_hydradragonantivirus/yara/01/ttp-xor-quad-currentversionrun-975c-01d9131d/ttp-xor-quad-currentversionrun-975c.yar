rule TTP_XOR_QUAD_CurrentVersionRun_975c {
  strings:
    $key_975c = { c4 33 [2] e0 3d [2] cb 11 [2] e5 33 [2] f1 28 [2] fe 32 [2] e0 2f [2] e2 2e [2] f9 28 [2] e5 2f [2] f9 00 }

  condition:
    any of them
}