rule TTP_XOR_MULT_DOSStub_df42 {
  strings:
    $key_df42 = { 8b 2a [2] ff 32 [2] b8 30 [2] ff 21 [2] b1 2d [2] bd 27 [2] aa 2c [2] b1 62 [2] 8c }

  condition:
    any of them
}