rule TTP_XOR_QUAD_CurrentVersionRun_87b3 {
  strings:
    $key_87b3 = { d4 dc [2] f0 d2 [2] db fe [2] f5 dc [2] e1 c7 [2] ee dd [2] f0 c0 [2] f2 c1 [2] e9 c7 [2] f5 c0 [2] e9 ef }

  condition:
    any of them
}