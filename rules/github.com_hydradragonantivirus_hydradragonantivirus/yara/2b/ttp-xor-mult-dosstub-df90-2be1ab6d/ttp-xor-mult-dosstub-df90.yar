rule TTP_XOR_MULT_DOSStub_df90 {
  strings:
    $key_df90 = { 8b f8 [2] ff e0 [2] b8 e2 [2] ff f3 [2] b1 ff [2] bd f5 [2] aa fe [2] b1 b0 [2] 8c }

  condition:
    any of them
}