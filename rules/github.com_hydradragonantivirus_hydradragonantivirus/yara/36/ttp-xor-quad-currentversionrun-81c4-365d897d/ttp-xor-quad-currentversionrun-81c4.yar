rule TTP_XOR_QUAD_CurrentVersionRun_81c4 {
  strings:
    $key_81c4 = { d2 ab [2] f6 a5 [2] dd 89 [2] f3 ab [2] e7 b0 [2] e8 aa [2] f6 b7 [2] f4 b6 [2] ef b0 [2] f3 b7 [2] ef 98 }

  condition:
    any of them
}