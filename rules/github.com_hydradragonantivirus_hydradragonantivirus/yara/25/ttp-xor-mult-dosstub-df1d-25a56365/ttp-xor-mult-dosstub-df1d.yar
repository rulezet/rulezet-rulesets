rule TTP_XOR_MULT_DOSStub_df1d {
  strings:
    $key_df1d = { 8b 75 [2] ff 6d [2] b8 6f [2] ff 7e [2] b1 72 [2] bd 78 [2] aa 73 [2] b1 3d [2] 8c }

  condition:
    any of them
}