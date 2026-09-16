rule TTP_XOR_QUAD_CurrentVersionRun_dd88 {
  strings:
    $key_dd88 = { 8e e7 [2] aa e9 [2] 81 c5 [2] af e7 [2] bb fc [2] b4 e6 [2] aa fb [2] a8 fa [2] b3 fc [2] af fb [2] b3 d4 }

  condition:
    any of them
}