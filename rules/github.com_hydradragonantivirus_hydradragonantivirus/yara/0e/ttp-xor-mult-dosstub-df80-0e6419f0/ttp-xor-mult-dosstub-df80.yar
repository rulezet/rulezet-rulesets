rule TTP_XOR_MULT_DOSStub_df80 {
  strings:
    $key_df80 = { 8b e8 [2] ff f0 [2] b8 f2 [2] ff e3 [2] b1 ef [2] bd e5 [2] aa ee [2] b1 a0 [2] 8c }

  condition:
    any of them
}