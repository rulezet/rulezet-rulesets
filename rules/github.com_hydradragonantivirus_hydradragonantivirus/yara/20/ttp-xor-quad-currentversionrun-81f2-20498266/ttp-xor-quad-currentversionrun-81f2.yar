rule TTP_XOR_QUAD_CurrentVersionRun_81f2 {
  strings:
    $key_81f2 = { d2 9d [2] f6 93 [2] dd bf [2] f3 9d [2] e7 86 [2] e8 9c [2] f6 81 [2] f4 80 [2] ef 86 [2] f3 81 [2] ef ae }

  condition:
    any of them
}