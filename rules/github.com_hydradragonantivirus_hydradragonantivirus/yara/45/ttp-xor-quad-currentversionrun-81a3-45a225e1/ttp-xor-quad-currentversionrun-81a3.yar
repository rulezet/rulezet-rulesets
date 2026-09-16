rule TTP_XOR_QUAD_CurrentVersionRun_81a3 {
  strings:
    $key_81a3 = { d2 cc [2] f6 c2 [2] dd ee [2] f3 cc [2] e7 d7 [2] e8 cd [2] f6 d0 [2] f4 d1 [2] ef d7 [2] f3 d0 [2] ef ff }

  condition:
    any of them
}