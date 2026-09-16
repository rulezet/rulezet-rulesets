rule TTP_XOR_MULT_DOSStub_df97 {
  strings:
    $key_df97 = { 8b ff [2] ff e7 [2] b8 e5 [2] ff f4 [2] b1 f8 [2] bd f2 [2] aa f9 [2] b1 b7 [2] 8c }

  condition:
    any of them
}