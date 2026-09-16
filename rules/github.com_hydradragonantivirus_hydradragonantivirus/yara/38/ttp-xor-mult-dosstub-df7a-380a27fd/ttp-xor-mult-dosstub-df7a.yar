rule TTP_XOR_MULT_DOSStub_df7a {
  strings:
    $key_df7a = { 8b 12 [2] ff 0a [2] b8 08 [2] ff 19 [2] b1 15 [2] bd 1f [2] aa 14 [2] b1 5a [2] 8c }

  condition:
    any of them
}