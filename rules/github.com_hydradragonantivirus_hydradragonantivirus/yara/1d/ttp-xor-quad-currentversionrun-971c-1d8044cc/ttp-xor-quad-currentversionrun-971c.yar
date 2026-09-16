rule TTP_XOR_QUAD_CurrentVersionRun_971c {
  strings:
    $key_971c = { c4 73 [2] e0 7d [2] cb 51 [2] e5 73 [2] f1 68 [2] fe 72 [2] e0 6f [2] e2 6e [2] f9 68 [2] e5 6f [2] f9 40 }

  condition:
    any of them
}