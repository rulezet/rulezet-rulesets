rule TTP_XOR_QUAD_CurrentVersionRun_81e5 {
  strings:
    $key_81e5 = { d2 8a [2] f6 84 [2] dd a8 [2] f3 8a [2] e7 91 [2] e8 8b [2] f6 96 [2] f4 97 [2] ef 91 [2] f3 96 [2] ef b9 }

  condition:
    any of them
}