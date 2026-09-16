rule TTP_XOR_MULT_DOSStub_df86 {
  strings:
    $key_df86 = { 8b ee [2] ff f6 [2] b8 f4 [2] ff e5 [2] b1 e9 [2] bd e3 [2] aa e8 [2] b1 a6 [2] 8c }

  condition:
    any of them
}