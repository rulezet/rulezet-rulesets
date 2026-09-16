rule TTP_XOR_MULT_DOSStub_df76 {
  strings:
    $key_df76 = { 8b 1e [2] ff 06 [2] b8 04 [2] ff 15 [2] b1 19 [2] bd 13 [2] aa 18 [2] b1 56 [2] 8c }

  condition:
    any of them
}