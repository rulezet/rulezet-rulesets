rule TTP_XOR_QUAD_CurrentVersionRun_976c {
  strings:
    $key_976c = { c4 03 [2] e0 0d [2] cb 21 [2] e5 03 [2] f1 18 [2] fe 02 [2] e0 1f [2] e2 1e [2] f9 18 [2] e5 1f [2] f9 30 }

  condition:
    any of them
}