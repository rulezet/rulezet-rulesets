rule TTP_XOR_QUAD_CurrentVersionRun_979c {
  strings:
    $key_979c = { c4 f3 [2] e0 fd [2] cb d1 [2] e5 f3 [2] f1 e8 [2] fe f2 [2] e0 ef [2] e2 ee [2] f9 e8 [2] e5 ef [2] f9 c0 }

  condition:
    any of them
}