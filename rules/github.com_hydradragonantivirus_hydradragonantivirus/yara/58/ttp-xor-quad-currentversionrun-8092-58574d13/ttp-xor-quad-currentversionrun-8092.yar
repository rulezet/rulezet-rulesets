rule TTP_XOR_QUAD_CurrentVersionRun_8092 {
  strings:
    $key_8092 = { d3 fd [2] f7 f3 [2] dc df [2] f2 fd [2] e6 e6 [2] e9 fc [2] f7 e1 [2] f5 e0 [2] ee e6 [2] f2 e1 [2] ee ce }

  condition:
    any of them
}