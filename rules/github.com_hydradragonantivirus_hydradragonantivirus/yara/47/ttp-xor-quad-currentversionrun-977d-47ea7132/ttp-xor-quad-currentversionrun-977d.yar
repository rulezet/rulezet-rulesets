rule TTP_XOR_QUAD_CurrentVersionRun_977d {
  strings:
    $key_977d = { c4 12 [2] e0 1c [2] cb 30 [2] e5 12 [2] f1 09 [2] fe 13 [2] e0 0e [2] e2 0f [2] f9 09 [2] e5 0e [2] f9 21 }

  condition:
    any of them
}