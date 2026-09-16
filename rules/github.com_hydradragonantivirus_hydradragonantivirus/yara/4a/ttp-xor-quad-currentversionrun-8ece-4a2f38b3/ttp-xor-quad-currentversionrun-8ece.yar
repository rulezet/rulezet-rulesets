rule TTP_XOR_QUAD_CurrentVersionRun_8ece {
  strings:
    $key_8ece = { dd a1 [2] f9 af [2] d2 83 [2] fc a1 [2] e8 ba [2] e7 a0 [2] f9 bd [2] fb bc [2] e0 ba [2] fc bd [2] e0 92 }

  condition:
    any of them
}