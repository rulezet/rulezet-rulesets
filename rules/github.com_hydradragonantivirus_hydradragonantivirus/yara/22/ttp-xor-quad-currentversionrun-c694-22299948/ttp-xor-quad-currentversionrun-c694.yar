rule TTP_XOR_QUAD_CurrentVersionRun_c694 {
  strings:
    $key_c694 = { 95 fb [2] b1 f5 [2] 9a d9 [2] b4 fb [2] a0 e0 [2] af fa [2] b1 e7 [2] b3 e6 [2] a8 e0 [2] b4 e7 [2] a8 c8 }

  condition:
    any of them
}