rule TTP_XOR_QUAD_CurrentVersionRun_86b2 {
  strings:
    $key_86b2 = { d5 dd [2] f1 d3 [2] da ff [2] f4 dd [2] e0 c6 [2] ef dc [2] f1 c1 [2] f3 c0 [2] e8 c6 [2] f4 c1 [2] e8 ee }

  condition:
    any of them
}