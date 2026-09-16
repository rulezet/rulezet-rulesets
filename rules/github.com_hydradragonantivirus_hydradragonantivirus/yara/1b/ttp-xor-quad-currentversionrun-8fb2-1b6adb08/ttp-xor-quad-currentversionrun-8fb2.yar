rule TTP_XOR_QUAD_CurrentVersionRun_8fb2 {
  strings:
    $key_8fb2 = { dc dd [2] f8 d3 [2] d3 ff [2] fd dd [2] e9 c6 [2] e6 dc [2] f8 c1 [2] fa c0 [2] e1 c6 [2] fd c1 [2] e1 ee }

  condition:
    any of them
}