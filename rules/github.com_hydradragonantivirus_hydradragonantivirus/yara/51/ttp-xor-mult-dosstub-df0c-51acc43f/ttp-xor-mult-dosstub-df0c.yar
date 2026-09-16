rule TTP_XOR_MULT_DOSStub_df0c {
  strings:
    $key_df0c = { 8b 64 [2] ff 7c [2] b8 7e [2] ff 6f [2] b1 63 [2] bd 69 [2] aa 62 [2] b1 2c [2] 8c }

  condition:
    any of them
}