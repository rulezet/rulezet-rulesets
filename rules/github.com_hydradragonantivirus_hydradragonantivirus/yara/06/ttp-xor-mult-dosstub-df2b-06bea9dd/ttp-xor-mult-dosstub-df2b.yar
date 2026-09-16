rule TTP_XOR_MULT_DOSStub_df2b {
  strings:
    $key_df2b = { 8b 43 [2] ff 5b [2] b8 59 [2] ff 48 [2] b1 44 [2] bd 4e [2] aa 45 [2] b1 0b [2] 8c }

  condition:
    any of them
}