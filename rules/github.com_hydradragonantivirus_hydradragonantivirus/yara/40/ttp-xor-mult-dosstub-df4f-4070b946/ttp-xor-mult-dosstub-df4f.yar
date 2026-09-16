rule TTP_XOR_MULT_DOSStub_df4f {
  strings:
    $key_df4f = { 8b 27 [2] ff 3f [2] b8 3d [2] ff 2c [2] b1 20 [2] bd 2a [2] aa 21 [2] b1 6f [2] 8c }

  condition:
    any of them
}