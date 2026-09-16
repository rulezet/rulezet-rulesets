rule TTP_XOR_QUAD_CurrentVersionRun_971e {
  strings:
    $key_971e = { c4 71 [2] e0 7f [2] cb 53 [2] e5 71 [2] f1 6a [2] fe 70 [2] e0 6d [2] e2 6c [2] f9 6a [2] e5 6d [2] f9 42 }

  condition:
    any of them
}