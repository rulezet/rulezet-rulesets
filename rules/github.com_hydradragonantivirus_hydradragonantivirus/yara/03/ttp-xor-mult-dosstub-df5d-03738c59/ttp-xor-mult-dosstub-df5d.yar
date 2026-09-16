rule TTP_XOR_MULT_DOSStub_df5d {
  strings:
    $key_df5d = { 8b 35 [2] ff 2d [2] b8 2f [2] ff 3e [2] b1 32 [2] bd 38 [2] aa 33 [2] b1 7d [2] 8c }

  condition:
    any of them
}