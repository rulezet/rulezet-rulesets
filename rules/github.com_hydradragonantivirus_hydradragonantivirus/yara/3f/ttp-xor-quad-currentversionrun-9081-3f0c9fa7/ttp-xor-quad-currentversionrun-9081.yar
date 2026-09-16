rule TTP_XOR_QUAD_CurrentVersionRun_9081 {
  strings:
    $key_9081 = { c3 ee [2] e7 e0 [2] cc cc [2] e2 ee [2] f6 f5 [2] f9 ef [2] e7 f2 [2] e5 f3 [2] fe f5 [2] e2 f2 [2] fe dd }

  condition:
    any of them
}