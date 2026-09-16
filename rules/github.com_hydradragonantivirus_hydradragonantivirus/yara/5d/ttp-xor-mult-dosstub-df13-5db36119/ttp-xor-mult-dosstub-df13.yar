rule TTP_XOR_MULT_DOSStub_df13 {
  strings:
    $key_df13 = { 8b 7b [2] ff 63 [2] b8 61 [2] ff 70 [2] b1 7c [2] bd 76 [2] aa 7d [2] b1 33 [2] 8c }

  condition:
    any of them
}