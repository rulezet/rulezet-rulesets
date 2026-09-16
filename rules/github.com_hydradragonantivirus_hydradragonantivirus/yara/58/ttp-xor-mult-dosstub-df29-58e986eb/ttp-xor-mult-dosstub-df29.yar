rule TTP_XOR_MULT_DOSStub_df29 {
  strings:
    $key_df29 = { 8b 41 [2] ff 59 [2] b8 5b [2] ff 4a [2] b1 46 [2] bd 4c [2] aa 47 [2] b1 09 [2] 8c }

  condition:
    any of them
}