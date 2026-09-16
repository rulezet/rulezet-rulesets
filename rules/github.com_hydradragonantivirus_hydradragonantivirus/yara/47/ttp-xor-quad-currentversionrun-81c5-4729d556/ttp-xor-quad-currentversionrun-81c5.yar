rule TTP_XOR_QUAD_CurrentVersionRun_81c5 {
  strings:
    $key_81c5 = { d2 aa [2] f6 a4 [2] dd 88 [2] f3 aa [2] e7 b1 [2] e8 ab [2] f6 b6 [2] f4 b7 [2] ef b1 [2] f3 b6 [2] ef 99 }

  condition:
    any of them
}