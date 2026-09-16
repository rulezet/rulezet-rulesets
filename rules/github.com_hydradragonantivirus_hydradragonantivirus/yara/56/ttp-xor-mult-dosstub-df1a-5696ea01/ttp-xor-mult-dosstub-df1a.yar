rule TTP_XOR_MULT_DOSStub_df1a {
  strings:
    $key_df1a = { 8b 72 [2] ff 6a [2] b8 68 [2] ff 79 [2] b1 75 [2] bd 7f [2] aa 74 [2] b1 3a [2] 8c }

  condition:
    any of them
}