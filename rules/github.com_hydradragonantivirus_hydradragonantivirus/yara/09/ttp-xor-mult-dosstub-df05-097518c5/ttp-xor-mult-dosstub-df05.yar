rule TTP_XOR_MULT_DOSStub_df05 {
  strings:
    $key_df05 = { 8b 6d [2] ff 75 [2] b8 77 [2] ff 66 [2] b1 6a [2] bd 60 [2] aa 6b [2] b1 25 [2] 8c }

  condition:
    any of them
}