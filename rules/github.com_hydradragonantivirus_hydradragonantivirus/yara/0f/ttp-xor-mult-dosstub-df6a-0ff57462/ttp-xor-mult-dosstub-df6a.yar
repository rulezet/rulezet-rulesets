rule TTP_XOR_MULT_DOSStub_df6a {
  strings:
    $key_df6a = { 8b 02 [2] ff 1a [2] b8 18 [2] ff 09 [2] b1 05 [2] bd 0f [2] aa 04 [2] b1 4a [2] 8c }

  condition:
    any of them
}