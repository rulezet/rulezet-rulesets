rule TTP_XOR_QUAD_CurrentVersionRun_87b2 {
  strings:
    $key_87b2 = { d4 dd [2] f0 d3 [2] db ff [2] f5 dd [2] e1 c6 [2] ee dc [2] f0 c1 [2] f2 c0 [2] e9 c6 [2] f5 c1 [2] e9 ee }

  condition:
    any of them
}