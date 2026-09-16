rule TTP_XOR_QUAD_CurrentVersionRun_3f95 {
  strings:
    $key_3f95 = { 6c fa [2] 48 f4 [2] 63 d8 [2] 4d fa [2] 59 e1 [2] 56 fb [2] 48 e6 [2] 4a e7 [2] 51 e1 [2] 4d e6 [2] 51 c9 }

  condition:
    any of them
}