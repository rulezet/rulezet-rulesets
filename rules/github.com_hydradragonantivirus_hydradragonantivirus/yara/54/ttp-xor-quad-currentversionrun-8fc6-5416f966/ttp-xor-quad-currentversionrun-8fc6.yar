rule TTP_XOR_QUAD_CurrentVersionRun_8fc6 {
  strings:
    $key_8fc6 = { dc a9 [2] f8 a7 [2] d3 8b [2] fd a9 [2] e9 b2 [2] e6 a8 [2] f8 b5 [2] fa b4 [2] e1 b2 [2] fd b5 [2] e1 9a }

  condition:
    any of them
}