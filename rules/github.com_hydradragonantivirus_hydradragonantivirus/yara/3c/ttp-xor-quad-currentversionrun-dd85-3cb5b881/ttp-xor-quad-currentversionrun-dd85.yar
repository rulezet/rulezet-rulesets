rule TTP_XOR_QUAD_CurrentVersionRun_dd85 {
  strings:
    $key_dd85 = { 8e ea [2] aa e4 [2] 81 c8 [2] af ea [2] bb f1 [2] b4 eb [2] aa f6 [2] a8 f7 [2] b3 f1 [2] af f6 [2] b3 d9 }

  condition:
    any of them
}