rule TTP_XOR_QUAD_CurrentVersionRun_81e8 {
  strings:
    $key_81e8 = { d2 87 [2] f6 89 [2] dd a5 [2] f3 87 [2] e7 9c [2] e8 86 [2] f6 9b [2] f4 9a [2] ef 9c [2] f3 9b [2] ef b4 }

  condition:
    any of them
}