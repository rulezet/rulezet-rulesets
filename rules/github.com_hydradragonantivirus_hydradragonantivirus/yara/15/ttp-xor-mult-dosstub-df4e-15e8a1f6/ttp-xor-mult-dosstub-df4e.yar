rule TTP_XOR_MULT_DOSStub_df4e {
  strings:
    $key_df4e = { 8b 26 [2] ff 3e [2] b8 3c [2] ff 2d [2] b1 21 [2] bd 2b [2] aa 20 [2] b1 6e [2] 8c }

  condition:
    any of them
}