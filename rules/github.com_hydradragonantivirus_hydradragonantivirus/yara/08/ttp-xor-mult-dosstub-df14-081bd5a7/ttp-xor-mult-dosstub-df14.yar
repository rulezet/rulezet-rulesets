rule TTP_XOR_MULT_DOSStub_df14 {
  strings:
    $key_df14 = { 8b 7c [2] ff 64 [2] b8 66 [2] ff 77 [2] b1 7b [2] bd 71 [2] aa 7a [2] b1 34 [2] 8c }

  condition:
    any of them
}