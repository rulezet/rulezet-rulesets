rule TTP_XOR_QUAD_CurrentVersionRun_af9c {
  strings:
    $key_af9c = { fc f3 [2] d8 fd [2] f3 d1 [2] dd f3 [2] c9 e8 [2] c6 f2 [2] d8 ef [2] da ee [2] c1 e8 [2] dd ef [2] c1 c0 }

  condition:
    any of them
}