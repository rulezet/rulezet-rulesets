rule TTP_XOR_QUAD_CurrentVersionRun_81b3 {
  strings:
    $key_81b3 = { d2 dc [2] f6 d2 [2] dd fe [2] f3 dc [2] e7 c7 [2] e8 dd [2] f6 c0 [2] f4 c1 [2] ef c7 [2] f3 c0 [2] ef ef }

  condition:
    any of them
}