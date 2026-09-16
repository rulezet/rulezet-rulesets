rule TTP_XOR_MULT_DOSStub_df78 {
  strings:
    $key_df78 = { 8b 10 [2] ff 08 [2] b8 0a [2] ff 1b [2] b1 17 [2] bd 1d [2] aa 16 [2] b1 58 [2] 8c }

  condition:
    any of them
}