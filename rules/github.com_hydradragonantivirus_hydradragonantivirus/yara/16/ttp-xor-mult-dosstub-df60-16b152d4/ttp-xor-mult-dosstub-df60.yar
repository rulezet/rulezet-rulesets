rule TTP_XOR_MULT_DOSStub_df60 {
  strings:
    $key_df60 = { 8b 08 [2] ff 10 [2] b8 12 [2] ff 03 [2] b1 0f [2] bd 05 [2] aa 0e [2] b1 40 [2] 8c }

  condition:
    any of them
}