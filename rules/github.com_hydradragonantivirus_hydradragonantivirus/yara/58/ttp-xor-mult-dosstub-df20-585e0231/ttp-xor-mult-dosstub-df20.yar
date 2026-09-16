rule TTP_XOR_MULT_DOSStub_df20 {
  strings:
    $key_df20 = { 8b 48 [2] ff 50 [2] b8 52 [2] ff 43 [2] b1 4f [2] bd 45 [2] aa 4e [2] b1 00 [2] 8c }

  condition:
    any of them
}