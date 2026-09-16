rule TTP_XOR_QUAD_CurrentVersionRun_0594 {
  strings:
    $key_0594 = { 56 fb [2] 72 f5 [2] 59 d9 [2] 77 fb [2] 63 e0 [2] 6c fa [2] 72 e7 [2] 70 e6 [2] 6b e0 [2] 77 e7 [2] 6b c8 }

  condition:
    any of them
}