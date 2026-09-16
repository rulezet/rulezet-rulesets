rule TTP_XOR_QUAD_CurrentVersionRun_81e9 {
  strings:
    $key_81e9 = { d2 86 [2] f6 88 [2] dd a4 [2] f3 86 [2] e7 9d [2] e8 87 [2] f6 9a [2] f4 9b [2] ef 9d [2] f3 9a [2] ef b5 }

  condition:
    any of them
}