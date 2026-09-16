rule TTP_XOR_QUAD_CurrentVersionRun_96b2 {
  strings:
    $key_96b2 = { c5 dd [2] e1 d3 [2] ca ff [2] e4 dd [2] f0 c6 [2] ff dc [2] e1 c1 [2] e3 c0 [2] f8 c6 [2] e4 c1 [2] f8 ee }

  condition:
    any of them
}