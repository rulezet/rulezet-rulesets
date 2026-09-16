rule TTP_XOR_QUAD_CurrentVersionRun_9ca2 {
  strings:
    $key_9ca2 = { cf cd [2] eb c3 [2] c0 ef [2] ee cd [2] fa d6 [2] f5 cc [2] eb d1 [2] e9 d0 [2] f2 d6 [2] ee d1 [2] f2 fe }

  condition:
    any of them
}