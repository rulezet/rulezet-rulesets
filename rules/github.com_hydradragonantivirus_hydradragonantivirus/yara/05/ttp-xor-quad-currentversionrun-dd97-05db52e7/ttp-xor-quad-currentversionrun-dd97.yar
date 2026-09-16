rule TTP_XOR_QUAD_CurrentVersionRun_dd97 {
  strings:
    $key_dd97 = { 8e f8 [2] aa f6 [2] 81 da [2] af f8 [2] bb e3 [2] b4 f9 [2] aa e4 [2] a8 e5 [2] b3 e3 [2] af e4 [2] b3 cb }

  condition:
    any of them
}