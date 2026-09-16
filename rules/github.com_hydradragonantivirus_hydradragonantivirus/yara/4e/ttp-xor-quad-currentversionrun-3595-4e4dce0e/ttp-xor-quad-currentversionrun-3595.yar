rule TTP_XOR_QUAD_CurrentVersionRun_3595 {
  strings:
    $key_3595 = { 66 fa [2] 42 f4 [2] 69 d8 [2] 47 fa [2] 53 e1 [2] 5c fb [2] 42 e6 [2] 40 e7 [2] 5b e1 [2] 47 e6 [2] 5b c9 }

  condition:
    any of them
}