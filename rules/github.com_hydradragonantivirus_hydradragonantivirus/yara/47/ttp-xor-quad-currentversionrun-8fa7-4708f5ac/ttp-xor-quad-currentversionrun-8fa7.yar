rule TTP_XOR_QUAD_CurrentVersionRun_8fa7 {
  strings:
    $key_8fa7 = { dc c8 [2] f8 c6 [2] d3 ea [2] fd c8 [2] e9 d3 [2] e6 c9 [2] f8 d4 [2] fa d5 [2] e1 d3 [2] fd d4 [2] e1 fb }

  condition:
    any of them
}