rule TTP_XOR_QUAD_CurrentVersionRun_8fce {
  strings:
    $key_8fce = { dc a1 [2] f8 af [2] d3 83 [2] fd a1 [2] e9 ba [2] e6 a0 [2] f8 bd [2] fa bc [2] e1 ba [2] fd bd [2] e1 92 }

  condition:
    any of them
}