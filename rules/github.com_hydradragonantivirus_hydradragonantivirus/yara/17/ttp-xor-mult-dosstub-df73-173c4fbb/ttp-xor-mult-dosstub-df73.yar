rule TTP_XOR_MULT_DOSStub_df73 {
  strings:
    $key_df73 = { 8b 1b [2] ff 03 [2] b8 01 [2] ff 10 [2] b1 1c [2] bd 16 [2] aa 1d [2] b1 53 [2] 8c }

  condition:
    any of them
}