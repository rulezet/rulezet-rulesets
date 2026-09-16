rule TTP_XOR_QUAD_CurrentVersionRun_939c {
  strings:
    $key_939c = { c0 f3 [2] e4 fd [2] cf d1 [2] e1 f3 [2] f5 e8 [2] fa f2 [2] e4 ef [2] e6 ee [2] fd e8 [2] e1 ef [2] fd c0 }

  condition:
    any of them
}