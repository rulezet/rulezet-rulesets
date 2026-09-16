rule TTP_XOR_QUAD_CurrentVersionRun_8fc1 {
  strings:
    $key_8fc1 = { dc ae [2] f8 a0 [2] d3 8c [2] fd ae [2] e9 b5 [2] e6 af [2] f8 b2 [2] fa b3 [2] e1 b5 [2] fd b2 [2] e1 9d }

  condition:
    any of them
}