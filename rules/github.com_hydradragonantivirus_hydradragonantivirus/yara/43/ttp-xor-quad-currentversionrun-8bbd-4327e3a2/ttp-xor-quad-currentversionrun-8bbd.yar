rule TTP_XOR_QUAD_CurrentVersionRun_8bbd {
  strings:
    $key_8bbd = { d8 d2 [2] fc dc [2] d7 f0 [2] f9 d2 [2] ed c9 [2] e2 d3 [2] fc ce [2] fe cf [2] e5 c9 [2] f9 ce [2] e5 e1 }

  condition:
    any of them
}