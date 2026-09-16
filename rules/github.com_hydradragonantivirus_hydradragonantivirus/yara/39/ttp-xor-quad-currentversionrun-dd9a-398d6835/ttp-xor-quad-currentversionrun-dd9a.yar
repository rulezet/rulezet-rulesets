rule TTP_XOR_QUAD_CurrentVersionRun_dd9a {
  strings:
    $key_dd9a = { 8e f5 [2] aa fb [2] 81 d7 [2] af f5 [2] bb ee [2] b4 f4 [2] aa e9 [2] a8 e8 [2] b3 ee [2] af e9 [2] b3 c6 }

  condition:
    any of them
}