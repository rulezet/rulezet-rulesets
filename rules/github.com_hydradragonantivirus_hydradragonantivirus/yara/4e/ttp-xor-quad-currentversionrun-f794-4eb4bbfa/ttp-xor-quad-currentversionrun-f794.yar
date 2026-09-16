rule TTP_XOR_QUAD_CurrentVersionRun_f794 {
  strings:
    $key_f794 = { a4 fb [2] 80 f5 [2] ab d9 [2] 85 fb [2] 91 e0 [2] 9e fa [2] 80 e7 [2] 82 e6 [2] 99 e0 [2] 85 e7 [2] 99 c8 }

  condition:
    any of them
}