rule TTP_XOR_QUAD_CurrentVersionRun_8fb7 {
  strings:
    $key_8fb7 = { dc d8 [2] f8 d6 [2] d3 fa [2] fd d8 [2] e9 c3 [2] e6 d9 [2] f8 c4 [2] fa c5 [2] e1 c3 [2] fd c4 [2] e1 eb }

  condition:
    any of them
}