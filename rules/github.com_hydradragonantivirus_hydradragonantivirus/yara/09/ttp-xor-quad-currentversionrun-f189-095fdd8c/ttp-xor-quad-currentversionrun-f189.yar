rule TTP_XOR_QUAD_CurrentVersionRun_f189 {
  strings:
    $key_f189 = { a2 e6 [2] 86 e8 [2] ad c4 [2] 83 e6 [2] 97 fd [2] 98 e7 [2] 86 fa [2] 84 fb [2] 9f fd [2] 83 fa [2] 9f d5 }

  condition:
    any of them
}