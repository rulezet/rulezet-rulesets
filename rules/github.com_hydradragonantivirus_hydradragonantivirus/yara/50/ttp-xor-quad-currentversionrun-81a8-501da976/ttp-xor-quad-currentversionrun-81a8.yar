rule TTP_XOR_QUAD_CurrentVersionRun_81a8 {
  strings:
    $key_81a8 = { d2 c7 [2] f6 c9 [2] dd e5 [2] f3 c7 [2] e7 dc [2] e8 c6 [2] f6 db [2] f4 da [2] ef dc [2] f3 db [2] ef f4 }

  condition:
    any of them
}