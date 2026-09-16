rule TTP_XOR_MULT_DOSStub_df66 {
  strings:
    $key_df66 = { 8b 0e [2] ff 16 [2] b8 14 [2] ff 05 [2] b1 09 [2] bd 03 [2] aa 08 [2] b1 46 [2] 8c }

  condition:
    any of them
}