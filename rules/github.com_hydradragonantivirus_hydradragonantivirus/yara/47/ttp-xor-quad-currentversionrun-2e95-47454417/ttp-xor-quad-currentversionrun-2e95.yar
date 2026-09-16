rule TTP_XOR_QUAD_CurrentVersionRun_2e95 {
  strings:
    $key_2e95 = { 7d fa [2] 59 f4 [2] 72 d8 [2] 5c fa [2] 48 e1 [2] 47 fb [2] 59 e6 [2] 5b e7 [2] 40 e1 [2] 5c e6 [2] 40 c9 }

  condition:
    any of them
}