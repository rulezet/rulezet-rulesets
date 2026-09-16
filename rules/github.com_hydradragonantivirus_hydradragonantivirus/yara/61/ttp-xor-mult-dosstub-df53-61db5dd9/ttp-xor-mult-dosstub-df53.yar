rule TTP_XOR_MULT_DOSStub_df53 {
  strings:
    $key_df53 = { 8b 3b [2] ff 23 [2] b8 21 [2] ff 30 [2] b1 3c [2] bd 36 [2] aa 3d [2] b1 73 [2] 8c }

  condition:
    any of them
}