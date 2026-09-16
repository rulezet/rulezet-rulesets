rule TTP_XOR_MULT_DOSStub_df59 {
  strings:
    $key_df59 = { 8b 31 [2] ff 29 [2] b8 2b [2] ff 3a [2] b1 36 [2] bd 3c [2] aa 37 [2] b1 79 [2] 8c }

  condition:
    any of them
}