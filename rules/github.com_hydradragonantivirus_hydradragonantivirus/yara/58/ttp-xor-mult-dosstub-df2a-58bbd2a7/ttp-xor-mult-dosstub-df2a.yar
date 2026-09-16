rule TTP_XOR_MULT_DOSStub_df2a {
  strings:
    $key_df2a = { 8b 42 [2] ff 5a [2] b8 58 [2] ff 49 [2] b1 45 [2] bd 4f [2] aa 44 [2] b1 0a [2] 8c }

  condition:
    any of them
}