rule TTP_XOR_QUAD_CurrentVersionRun_81e2 {
  strings:
    $key_81e2 = { d2 8d [2] f6 83 [2] dd af [2] f3 8d [2] e7 96 [2] e8 8c [2] f6 91 [2] f4 90 [2] ef 96 [2] f3 91 [2] ef be }

  condition:
    any of them
}