rule TTP_XOR_QUAD_CurrentVersionRun_81ba {
  strings:
    $key_81ba = { d2 d5 [2] f6 db [2] dd f7 [2] f3 d5 [2] e7 ce [2] e8 d4 [2] f6 c9 [2] f4 c8 [2] ef ce [2] f3 c9 [2] ef e6 }

  condition:
    any of them
}