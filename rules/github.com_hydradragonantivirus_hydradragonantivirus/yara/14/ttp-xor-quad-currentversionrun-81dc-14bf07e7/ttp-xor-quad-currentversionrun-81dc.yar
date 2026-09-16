rule TTP_XOR_QUAD_CurrentVersionRun_81dc {
  strings:
    $key_81dc = { d2 b3 [2] f6 bd [2] dd 91 [2] f3 b3 [2] e7 a8 [2] e8 b2 [2] f6 af [2] f4 ae [2] ef a8 [2] f3 af [2] ef 80 }

  condition:
    any of them
}