rule TTP_XOR_QUAD_CurrentVersionRun_ef95 {
  strings:
    $key_ef95 = { bc fa [2] 98 f4 [2] b3 d8 [2] 9d fa [2] 89 e1 [2] 86 fb [2] 98 e6 [2] 9a e7 [2] 81 e1 [2] 9d e6 [2] 81 c9 }

  condition:
    any of them
}