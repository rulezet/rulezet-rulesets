rule TTP_XOR_MULT_DOSStub_df70 {
  strings:
    $key_df70 = { 8b 18 [2] ff 00 [2] b8 02 [2] ff 13 [2] b1 1f [2] bd 15 [2] aa 1e [2] b1 50 [2] 8c }

  condition:
    any of them
}