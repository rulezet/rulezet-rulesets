rule TTP_XOR_MULT_DOSStub_df71 {
  strings:
    $key_df71 = { 8b 19 [2] ff 01 [2] b8 03 [2] ff 12 [2] b1 1e [2] bd 14 [2] aa 1f [2] b1 51 [2] 8c }

  condition:
    any of them
}