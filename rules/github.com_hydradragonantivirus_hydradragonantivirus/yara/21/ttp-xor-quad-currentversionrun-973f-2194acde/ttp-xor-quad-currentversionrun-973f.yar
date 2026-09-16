rule TTP_XOR_QUAD_CurrentVersionRun_973f {
  strings:
    $key_973f = { c4 50 [2] e0 5e [2] cb 72 [2] e5 50 [2] f1 4b [2] fe 51 [2] e0 4c [2] e2 4d [2] f9 4b [2] e5 4c [2] f9 63 }

  condition:
    any of them
}