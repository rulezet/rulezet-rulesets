rule TTP_XOR_MULT_DOSStub_df44 {
  strings:
    $key_df44 = { 8b 2c [2] ff 34 [2] b8 36 [2] ff 27 [2] b1 2b [2] bd 21 [2] aa 2a [2] b1 64 [2] 8c }

  condition:
    any of them
}