rule TTP_XOR_QUAD_CurrentVersionRun_ff89 {
  strings:
    $key_ff89 = { ac e6 [2] 88 e8 [2] a3 c4 [2] 8d e6 [2] 99 fd [2] 96 e7 [2] 88 fa [2] 8a fb [2] 91 fd [2] 8d fa [2] 91 d5 }

  condition:
    any of them
}