rule TTP_XOR_QUAD_CurrentVersionRun_81d0 {
  strings:
    $key_81d0 = { d2 bf [2] f6 b1 [2] dd 9d [2] f3 bf [2] e7 a4 [2] e8 be [2] f6 a3 [2] f4 a2 [2] ef a4 [2] f3 a3 [2] ef 8c }

  condition:
    any of them
}