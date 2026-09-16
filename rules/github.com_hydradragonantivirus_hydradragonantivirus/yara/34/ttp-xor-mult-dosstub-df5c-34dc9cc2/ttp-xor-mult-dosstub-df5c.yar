rule TTP_XOR_MULT_DOSStub_df5c {
  strings:
    $key_df5c = { 8b 34 [2] ff 2c [2] b8 2e [2] ff 3f [2] b1 33 [2] bd 39 [2] aa 32 [2] b1 7c [2] 8c }

  condition:
    any of them
}