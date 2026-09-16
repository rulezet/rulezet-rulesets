rule TTP_XOR_MULT_DOSStub_df27 {
  strings:
    $key_df27 = { 8b 4f [2] ff 57 [2] b8 55 [2] ff 44 [2] b1 48 [2] bd 42 [2] aa 49 [2] b1 07 [2] 8c }

  condition:
    any of them
}