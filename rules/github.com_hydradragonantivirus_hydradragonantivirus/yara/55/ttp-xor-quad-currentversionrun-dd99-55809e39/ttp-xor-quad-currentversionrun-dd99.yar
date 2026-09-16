rule TTP_XOR_QUAD_CurrentVersionRun_dd99 {
  strings:
    $key_dd99 = { 8e f6 [2] aa f8 [2] 81 d4 [2] af f6 [2] bb ed [2] b4 f7 [2] aa ea [2] a8 eb [2] b3 ed [2] af ea [2] b3 c5 }

  condition:
    any of them
}