rule TTP_XOR_MULT_DOSStub_df08 {
  strings:
    $key_df08 = { 8b 60 [2] ff 78 [2] b8 7a [2] ff 6b [2] b1 67 [2] bd 6d [2] aa 66 [2] b1 28 [2] 8c }

  condition:
    any of them
}