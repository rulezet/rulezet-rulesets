rule TTP_XOR_QUAD_CurrentVersionRun_8fd6 {
  strings:
    $key_8fd6 = { dc b9 [2] f8 b7 [2] d3 9b [2] fd b9 [2] e9 a2 [2] e6 b8 [2] f8 a5 [2] fa a4 [2] e1 a2 [2] fd a5 [2] e1 8a }

  condition:
    any of them
}