rule TTP_XOR_QUAD_CurrentVersionRun_8e9c {
  strings:
    $key_8e9c = { dd f3 [2] f9 fd [2] d2 d1 [2] fc f3 [2] e8 e8 [2] e7 f2 [2] f9 ef [2] fb ee [2] e0 e8 [2] fc ef [2] e0 c0 }

  condition:
    any of them
}