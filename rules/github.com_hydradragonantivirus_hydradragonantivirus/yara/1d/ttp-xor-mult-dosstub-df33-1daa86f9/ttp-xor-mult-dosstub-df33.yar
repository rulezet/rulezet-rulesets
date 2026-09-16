rule TTP_XOR_MULT_DOSStub_df33 {
  strings:
    $key_df33 = { 8b 5b [2] ff 43 [2] b8 41 [2] ff 50 [2] b1 5c [2] bd 56 [2] aa 5d [2] b1 13 [2] 8c }

  condition:
    any of them
}