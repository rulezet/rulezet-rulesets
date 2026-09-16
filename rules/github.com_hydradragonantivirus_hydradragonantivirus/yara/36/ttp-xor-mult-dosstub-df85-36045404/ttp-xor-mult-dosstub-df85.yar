rule TTP_XOR_MULT_DOSStub_df85 {
  strings:
    $key_df85 = { 8b ed [2] ff f5 [2] b8 f7 [2] ff e6 [2] b1 ea [2] bd e0 [2] aa eb [2] b1 a5 [2] 8c }

  condition:
    any of them
}