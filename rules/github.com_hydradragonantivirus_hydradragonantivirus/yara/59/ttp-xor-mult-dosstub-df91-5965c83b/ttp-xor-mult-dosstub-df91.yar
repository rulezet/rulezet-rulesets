rule TTP_XOR_MULT_DOSStub_df91 {
  strings:
    $key_df91 = { 8b f9 [2] ff e1 [2] b8 e3 [2] ff f2 [2] b1 fe [2] bd f4 [2] aa ff [2] b1 b1 [2] 8c }

  condition:
    any of them
}