rule TTP_XOR_QUAD_CurrentVersionRun_2c95 {
  strings:
    $key_2c95 = { 7f fa [2] 5b f4 [2] 70 d8 [2] 5e fa [2] 4a e1 [2] 45 fb [2] 5b e6 [2] 59 e7 [2] 42 e1 [2] 5e e6 [2] 42 c9 }

  condition:
    any of them
}