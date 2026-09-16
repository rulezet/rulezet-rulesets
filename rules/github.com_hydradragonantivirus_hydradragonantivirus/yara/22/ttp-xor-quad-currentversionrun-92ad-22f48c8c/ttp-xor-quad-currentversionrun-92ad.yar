rule TTP_XOR_QUAD_CurrentVersionRun_92ad {
  strings:
    $key_92ad = { c1 c2 [2] e5 cc [2] ce e0 [2] e0 c2 [2] f4 d9 [2] fb c3 [2] e5 de [2] e7 df [2] fc d9 [2] e0 de [2] fc f1 }

  condition:
    any of them
}