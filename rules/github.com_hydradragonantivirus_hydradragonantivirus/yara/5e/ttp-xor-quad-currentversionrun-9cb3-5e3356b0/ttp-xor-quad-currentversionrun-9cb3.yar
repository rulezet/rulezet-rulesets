rule TTP_XOR_QUAD_CurrentVersionRun_9cb3 {
  strings:
    $key_9cb3 = { cf dc [2] eb d2 [2] c0 fe [2] ee dc [2] fa c7 [2] f5 dd [2] eb c0 [2] e9 c1 [2] f2 c7 [2] ee c0 [2] f2 ef }

  condition:
    any of them
}