rule TTP_XOR_MULT_DOSStub_df24 {
  strings:
    $key_df24 = { 8b 4c [2] ff 54 [2] b8 56 [2] ff 47 [2] b1 4b [2] bd 41 [2] aa 4a [2] b1 04 [2] 8c }

  condition:
    any of them
}