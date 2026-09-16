rule TTP_XOR_QUAD_CurrentVersionRun_81e4 {
  strings:
    $key_81e4 = { d2 8b [2] f6 85 [2] dd a9 [2] f3 8b [2] e7 90 [2] e8 8a [2] f6 97 [2] f4 96 [2] ef 90 [2] f3 97 [2] ef b8 }

  condition:
    any of them
}