rule TTP_XOR_MULT_DOSStub_df62 {
  strings:
    $key_df62 = { 8b 0a [2] ff 12 [2] b8 10 [2] ff 01 [2] b1 0d [2] bd 07 [2] aa 0c [2] b1 42 [2] 8c }

  condition:
    any of them
}