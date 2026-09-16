rule TTP_XOR_QUAD_CurrentVersionRun_81d2 {
  strings:
    $key_81d2 = { d2 bd [2] f6 b3 [2] dd 9f [2] f3 bd [2] e7 a6 [2] e8 bc [2] f6 a1 [2] f4 a0 [2] ef a6 [2] f3 a1 [2] ef 8e }

  condition:
    any of them
}