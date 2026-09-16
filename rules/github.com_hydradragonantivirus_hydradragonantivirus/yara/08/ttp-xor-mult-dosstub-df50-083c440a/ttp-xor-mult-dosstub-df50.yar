rule TTP_XOR_MULT_DOSStub_df50 {
  strings:
    $key_df50 = { 8b 38 [2] ff 20 [2] b8 22 [2] ff 33 [2] b1 3f [2] bd 35 [2] aa 3e [2] b1 70 [2] 8c }

  condition:
    any of them
}