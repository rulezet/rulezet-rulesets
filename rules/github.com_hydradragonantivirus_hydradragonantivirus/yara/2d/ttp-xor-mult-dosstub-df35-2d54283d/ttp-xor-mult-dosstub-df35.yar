rule TTP_XOR_MULT_DOSStub_df35 {
  strings:
    $key_df35 = { 8b 5d [2] ff 45 [2] b8 47 [2] ff 56 [2] b1 5a [2] bd 50 [2] aa 5b [2] b1 15 [2] 8c }

  condition:
    any of them
}