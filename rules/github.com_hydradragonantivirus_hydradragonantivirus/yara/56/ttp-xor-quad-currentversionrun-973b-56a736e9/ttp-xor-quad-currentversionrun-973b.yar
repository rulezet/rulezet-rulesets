rule TTP_XOR_QUAD_CurrentVersionRun_973b {
  strings:
    $key_973b = { c4 54 [2] e0 5a [2] cb 76 [2] e5 54 [2] f1 4f [2] fe 55 [2] e0 48 [2] e2 49 [2] f9 4f [2] e5 48 [2] f9 67 }

  condition:
    any of them
}