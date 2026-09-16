rule TTP_XOR_MULT_DOSStub_df2d {
  strings:
    $key_df2d = { 8b 45 [2] ff 5d [2] b8 5f [2] ff 4e [2] b1 42 [2] bd 48 [2] aa 43 [2] b1 0d [2] 8c }

  condition:
    any of them
}