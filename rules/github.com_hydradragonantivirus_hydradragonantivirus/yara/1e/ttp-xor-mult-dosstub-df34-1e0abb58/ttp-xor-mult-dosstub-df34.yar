rule TTP_XOR_MULT_DOSStub_df34 {
  strings:
    $key_df34 = { 8b 5c [2] ff 44 [2] b8 46 [2] ff 57 [2] b1 5b [2] bd 51 [2] aa 5a [2] b1 14 [2] 8c }

  condition:
    any of them
}