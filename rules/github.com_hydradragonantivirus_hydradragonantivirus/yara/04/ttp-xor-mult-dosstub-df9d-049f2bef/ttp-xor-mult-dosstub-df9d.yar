rule TTP_XOR_MULT_DOSStub_df9d {
  strings:
    $key_df9d = { 8b f5 [2] ff ed [2] b8 ef [2] ff fe [2] b1 f2 [2] bd f8 [2] aa f3 [2] b1 bd [2] 8c }

  condition:
    any of them
}