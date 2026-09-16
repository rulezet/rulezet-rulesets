rule TTP_XOR_MULT_DOSStub_df07 {
  strings:
    $key_df07 = { 8b 6f [2] ff 77 [2] b8 75 [2] ff 64 [2] b1 68 [2] bd 62 [2] aa 69 [2] b1 27 [2] 8c }

  condition:
    any of them
}