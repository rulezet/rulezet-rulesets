rule TTP_XOR_MULT_DOSStub_df4b {
  strings:
    $key_df4b = { 8b 23 [2] ff 3b [2] b8 39 [2] ff 28 [2] b1 24 [2] bd 2e [2] aa 25 [2] b1 6b [2] 8c }

  condition:
    any of them
}