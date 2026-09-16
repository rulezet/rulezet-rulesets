rule TTP_XOR_QUAD_CurrentVersionRun_8fc3 {
  strings:
    $key_8fc3 = { dc ac [2] f8 a2 [2] d3 8e [2] fd ac [2] e9 b7 [2] e6 ad [2] f8 b0 [2] fa b1 [2] e1 b7 [2] fd b0 [2] e1 9f }

  condition:
    any of them
}