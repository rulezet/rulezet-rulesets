rule TTP_XOR_MULT_DOSStub_df16 {
  strings:
    $key_df16 = { 8b 7e [2] ff 66 [2] b8 64 [2] ff 75 [2] b1 79 [2] bd 73 [2] aa 78 [2] b1 36 [2] 8c }

  condition:
    any of them
}