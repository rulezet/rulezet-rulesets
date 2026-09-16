rule TTP_XOR_QUAD_CurrentVersionRun_d885 {
  strings:
    $key_d885 = { 8b ea [2] af e4 [2] 84 c8 [2] aa ea [2] be f1 [2] b1 eb [2] af f6 [2] ad f7 [2] b6 f1 [2] aa f6 [2] b6 d9 }

  condition:
    any of them
}