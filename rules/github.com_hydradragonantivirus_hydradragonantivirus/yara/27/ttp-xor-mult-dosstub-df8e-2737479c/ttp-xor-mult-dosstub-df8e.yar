rule TTP_XOR_MULT_DOSStub_df8e {
  strings:
    $key_df8e = { 8b e6 [2] ff fe [2] b8 fc [2] ff ed [2] b1 e1 [2] bd eb [2] aa e0 [2] b1 ae [2] 8c }

  condition:
    any of them
}