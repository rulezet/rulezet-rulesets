rule TTP_XOR_MULT_DOSStub_df57 {
  strings:
    $key_df57 = { 8b 3f [2] ff 27 [2] b8 25 [2] ff 34 [2] b1 38 [2] bd 32 [2] aa 39 [2] b1 77 [2] 8c }

  condition:
    any of them
}