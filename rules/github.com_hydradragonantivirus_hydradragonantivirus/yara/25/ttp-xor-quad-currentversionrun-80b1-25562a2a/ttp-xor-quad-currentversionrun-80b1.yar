rule TTP_XOR_QUAD_CurrentVersionRun_80b1 {
  strings:
    $key_80b1 = { d3 de [2] f7 d0 [2] dc fc [2] f2 de [2] e6 c5 [2] e9 df [2] f7 c2 [2] f5 c3 [2] ee c5 [2] f2 c2 [2] ee ed }

  condition:
    any of them
}