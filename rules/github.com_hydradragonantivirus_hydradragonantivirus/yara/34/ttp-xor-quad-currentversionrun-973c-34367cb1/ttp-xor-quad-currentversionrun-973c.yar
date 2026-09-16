rule TTP_XOR_QUAD_CurrentVersionRun_973c {
  strings:
    $key_973c = { c4 53 [2] e0 5d [2] cb 71 [2] e5 53 [2] f1 48 [2] fe 52 [2] e0 4f [2] e2 4e [2] f9 48 [2] e5 4f [2] f9 60 }

  condition:
    any of them
}