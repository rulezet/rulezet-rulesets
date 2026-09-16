rule TTP_XOR_MULT_DOSStub_df49 {
  strings:
    $key_df49 = { 8b 21 [2] ff 39 [2] b8 3b [2] ff 2a [2] b1 26 [2] bd 2c [2] aa 27 [2] b1 69 [2] 8c }

  condition:
    any of them
}