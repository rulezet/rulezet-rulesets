rule TTP_XOR_MULT_DOSStub_df98 {
  strings:
    $key_df98 = { 8b f0 [2] ff e8 [2] b8 ea [2] ff fb [2] b1 f7 [2] bd fd [2] aa f6 [2] b1 b8 [2] 8c }

  condition:
    any of them
}