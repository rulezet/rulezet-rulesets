rule TTP_XOR_MULT_DOSStub_df7e {
  strings:
    $key_df7e = { 8b 16 [2] ff 0e [2] b8 0c [2] ff 1d [2] b1 11 [2] bd 1b [2] aa 10 [2] b1 5e [2] 8c }

  condition:
    any of them
}