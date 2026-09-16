rule TTP_XOR_QUAD_CurrentVersionRun_93a3 {
  strings:
    $key_93a3 = { c0 cc [2] e4 c2 [2] cf ee [2] e1 cc [2] f5 d7 [2] fa cd [2] e4 d0 [2] e6 d1 [2] fd d7 [2] e1 d0 [2] fd ff }

  condition:
    any of them
}