rule TTP_XOR_QUAD_CurrentVersionRun_819c {
  strings:
    $key_819c = { d2 f3 [2] f6 fd [2] dd d1 [2] f3 f3 [2] e7 e8 [2] e8 f2 [2] f6 ef [2] f4 ee [2] ef e8 [2] f3 ef [2] ef c0 }

  condition:
    any of them
}