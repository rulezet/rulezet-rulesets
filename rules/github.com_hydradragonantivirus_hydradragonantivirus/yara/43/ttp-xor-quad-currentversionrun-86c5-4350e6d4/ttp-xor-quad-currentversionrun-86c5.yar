rule TTP_XOR_QUAD_CurrentVersionRun_86c5 {
  strings:
    $key_86c5 = { d5 aa [2] f1 a4 [2] da 88 [2] f4 aa [2] e0 b1 [2] ef ab [2] f1 b6 [2] f3 b7 [2] e8 b1 [2] f4 b6 [2] e8 99 }

  condition:
    any of them
}