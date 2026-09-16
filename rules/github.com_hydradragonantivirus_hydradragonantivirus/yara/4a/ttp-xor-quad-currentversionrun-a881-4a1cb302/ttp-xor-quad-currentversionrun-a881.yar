rule TTP_XOR_QUAD_CurrentVersionRun_a881 {
  strings:
    $key_a881 = { fb ee [2] df e0 [2] f4 cc [2] da ee [2] ce f5 [2] c1 ef [2] df f2 [2] dd f3 [2] c6 f5 [2] da f2 [2] c6 dd }

  condition:
    any of them
}