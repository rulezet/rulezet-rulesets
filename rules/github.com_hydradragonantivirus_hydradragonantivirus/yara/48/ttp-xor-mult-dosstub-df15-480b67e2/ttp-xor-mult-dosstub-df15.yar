rule TTP_XOR_MULT_DOSStub_df15 {
  strings:
    $key_df15 = { 8b 7d [2] ff 65 [2] b8 67 [2] ff 76 [2] b1 7a [2] bd 70 [2] aa 7b [2] b1 35 [2] 8c }

  condition:
    any of them
}