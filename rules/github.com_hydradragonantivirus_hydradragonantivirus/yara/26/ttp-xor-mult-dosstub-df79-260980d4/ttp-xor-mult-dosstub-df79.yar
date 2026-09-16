rule TTP_XOR_MULT_DOSStub_df79 {
  strings:
    $key_df79 = { 8b 11 [2] ff 09 [2] b8 0b [2] ff 1a [2] b1 16 [2] bd 1c [2] aa 17 [2] b1 59 [2] 8c }

  condition:
    any of them
}