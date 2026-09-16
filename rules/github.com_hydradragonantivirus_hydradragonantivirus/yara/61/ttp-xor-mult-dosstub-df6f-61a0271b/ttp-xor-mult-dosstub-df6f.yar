rule TTP_XOR_MULT_DOSStub_df6f {
  strings:
    $key_df6f = { 8b 07 [2] ff 1f [2] b8 1d [2] ff 0c [2] b1 00 [2] bd 0a [2] aa 01 [2] b1 4f [2] 8c }

  condition:
    any of them
}