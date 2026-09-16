rule TTP_XOR_QUAD_CurrentVersionRun_81a2 {
  strings:
    $key_81a2 = { d2 cd [2] f6 c3 [2] dd ef [2] f3 cd [2] e7 d6 [2] e8 cc [2] f6 d1 [2] f4 d0 [2] ef d6 [2] f3 d1 [2] ef fe }

  condition:
    any of them
}