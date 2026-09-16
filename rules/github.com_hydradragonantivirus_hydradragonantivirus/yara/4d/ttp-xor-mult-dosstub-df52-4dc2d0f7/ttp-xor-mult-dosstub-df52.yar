rule TTP_XOR_MULT_DOSStub_df52 {
  strings:
    $key_df52 = { 8b 3a [2] ff 22 [2] b8 20 [2] ff 31 [2] b1 3d [2] bd 37 [2] aa 3c [2] b1 72 [2] 8c }

  condition:
    any of them
}