rule TTP_XOR_MULT_DOSStub_df51 {
  strings:
    $key_df51 = { 8b 39 [2] ff 21 [2] b8 23 [2] ff 32 [2] b1 3e [2] bd 34 [2] aa 3f [2] b1 71 [2] 8c }

  condition:
    any of them
}