rule TTP_XOR_QUAD_CurrentVersionRun_8614 {
  strings:
    $key_8614 = { d5 7b [2] f1 75 [2] da 59 [2] f4 7b [2] e0 60 [2] ef 7a [2] f1 67 [2] f3 66 [2] e8 60 [2] f4 67 [2] e8 48 }

  condition:
    any of them
}