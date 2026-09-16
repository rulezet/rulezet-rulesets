rule TTP_XOR_MULT_DOSStub_df69 {
  strings:
    $key_df69 = { 8b 01 [2] ff 19 [2] b8 1b [2] ff 0a [2] b1 06 [2] bd 0c [2] aa 07 [2] b1 49 [2] 8c }

  condition:
    any of them
}