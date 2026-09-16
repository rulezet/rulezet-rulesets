rule TTP_XOR_MULT_DOSStub_df7c {
  strings:
    $key_df7c = { 8b 14 [2] ff 0c [2] b8 0e [2] ff 1f [2] b1 13 [2] bd 19 [2] aa 12 [2] b1 5c [2] 8c }

  condition:
    any of them
}