rule TTP_XOR_MULT_DOSStub_df74 {
  strings:
    $key_df74 = { 8b 1c [2] ff 04 [2] b8 06 [2] ff 17 [2] b1 1b [2] bd 11 [2] aa 1a [2] b1 54 [2] 8c }

  condition:
    any of them
}