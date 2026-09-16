rule TTP_XOR_QUAD_CurrentVersionRun_f789 {
  strings:
    $key_f789 = { a4 e6 [2] 80 e8 [2] ab c4 [2] 85 e6 [2] 91 fd [2] 9e e7 [2] 80 fa [2] 82 fb [2] 99 fd [2] 85 fa [2] 99 d5 }

  condition:
    any of them
}