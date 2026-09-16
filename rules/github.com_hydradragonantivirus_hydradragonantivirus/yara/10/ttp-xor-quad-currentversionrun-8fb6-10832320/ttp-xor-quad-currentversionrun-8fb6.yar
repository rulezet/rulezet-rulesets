rule TTP_XOR_QUAD_CurrentVersionRun_8fb6 {
  strings:
    $key_8fb6 = { dc d9 [2] f8 d7 [2] d3 fb [2] fd d9 [2] e9 c2 [2] e6 d8 [2] f8 c5 [2] fa c4 [2] e1 c2 [2] fd c5 [2] e1 ea }

  condition:
    any of them
}