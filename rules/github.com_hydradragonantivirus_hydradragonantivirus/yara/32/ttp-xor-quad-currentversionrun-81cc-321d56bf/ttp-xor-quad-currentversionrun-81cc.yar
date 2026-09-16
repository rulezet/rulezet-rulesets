rule TTP_XOR_QUAD_CurrentVersionRun_81cc {
  strings:
    $key_81cc = { d2 a3 [2] f6 ad [2] dd 81 [2] f3 a3 [2] e7 b8 [2] e8 a2 [2] f6 bf [2] f4 be [2] ef b8 [2] f3 bf [2] ef 90 }

  condition:
    any of them
}