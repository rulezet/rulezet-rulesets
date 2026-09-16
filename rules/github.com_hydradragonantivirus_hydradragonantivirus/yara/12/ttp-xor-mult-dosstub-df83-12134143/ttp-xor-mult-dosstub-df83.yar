rule TTP_XOR_MULT_DOSStub_df83 {
  strings:
    $key_df83 = { 8b eb [2] ff f3 [2] b8 f1 [2] ff e0 [2] b1 ec [2] bd e6 [2] aa ed [2] b1 a3 [2] 8c }

  condition:
    any of them
}