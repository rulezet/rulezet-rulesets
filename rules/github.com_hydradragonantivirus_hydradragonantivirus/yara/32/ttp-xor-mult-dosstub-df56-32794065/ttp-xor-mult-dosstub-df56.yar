rule TTP_XOR_MULT_DOSStub_df56 {
  strings:
    $key_df56 = { 8b 3e [2] ff 26 [2] b8 24 [2] ff 35 [2] b1 39 [2] bd 33 [2] aa 38 [2] b1 76 [2] 8c }

  condition:
    any of them
}