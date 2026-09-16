rule TTP_XOR_QUAD_CurrentVersionRun_81d8 {
  strings:
    $key_81d8 = { d2 b7 [2] f6 b9 [2] dd 95 [2] f3 b7 [2] e7 ac [2] e8 b6 [2] f6 ab [2] f4 aa [2] ef ac [2] f3 ab [2] ef 84 }

  condition:
    any of them
}