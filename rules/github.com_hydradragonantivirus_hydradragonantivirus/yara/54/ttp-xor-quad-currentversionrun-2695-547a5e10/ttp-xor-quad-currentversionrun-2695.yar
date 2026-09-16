rule TTP_XOR_QUAD_CurrentVersionRun_2695 {
  strings:
    $key_2695 = { 75 fa [2] 51 f4 [2] 7a d8 [2] 54 fa [2] 40 e1 [2] 4f fb [2] 51 e6 [2] 53 e7 [2] 48 e1 [2] 54 e6 [2] 48 c9 }

  condition:
    any of them
}