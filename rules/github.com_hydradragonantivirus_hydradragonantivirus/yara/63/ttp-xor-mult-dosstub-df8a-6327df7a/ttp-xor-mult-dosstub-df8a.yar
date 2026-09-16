rule TTP_XOR_MULT_DOSStub_df8a {
  strings:
    $key_df8a = { 8b e2 [2] ff fa [2] b8 f8 [2] ff e9 [2] b1 e5 [2] bd ef [2] aa e4 [2] b1 aa [2] 8c }

  condition:
    any of them
}