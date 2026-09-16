rule TTP_XOR_QUAD_CurrentVersionRun_976e {
  strings:
    $key_976e = { c4 01 [2] e0 0f [2] cb 23 [2] e5 01 [2] f1 1a [2] fe 00 [2] e0 1d [2] e2 1c [2] f9 1a [2] e5 1d [2] f9 32 }

  condition:
    any of them
}