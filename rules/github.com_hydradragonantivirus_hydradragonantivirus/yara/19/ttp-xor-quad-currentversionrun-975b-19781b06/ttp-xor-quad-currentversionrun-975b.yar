rule TTP_XOR_QUAD_CurrentVersionRun_975b {
  strings:
    $key_975b = { c4 34 [2] e0 3a [2] cb 16 [2] e5 34 [2] f1 2f [2] fe 35 [2] e0 28 [2] e2 29 [2] f9 2f [2] e5 28 [2] f9 07 }

  condition:
    any of them
}