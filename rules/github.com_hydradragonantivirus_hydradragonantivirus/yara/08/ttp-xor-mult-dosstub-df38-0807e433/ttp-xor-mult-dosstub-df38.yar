rule TTP_XOR_MULT_DOSStub_df38 {
  strings:
    $key_df38 = { 8b 50 [2] ff 48 [2] b8 4a [2] ff 5b [2] b1 57 [2] bd 5d [2] aa 56 [2] b1 18 [2] 8c }

  condition:
    any of them
}