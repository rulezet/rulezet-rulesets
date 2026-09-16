rule TTP_XOR_QUAD_CurrentVersionRun_976a {
  strings:
    $key_976a = { c4 05 [2] e0 0b [2] cb 27 [2] e5 05 [2] f1 1e [2] fe 04 [2] e0 19 [2] e2 18 [2] f9 1e [2] e5 19 [2] f9 36 }

  condition:
    any of them
}