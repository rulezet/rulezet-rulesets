rule TTP_XOR_MULT_DOSStub_df82 {
  strings:
    $key_df82 = { 8b ea [2] ff f2 [2] b8 f0 [2] ff e1 [2] b1 ed [2] bd e7 [2] aa ec [2] b1 a2 [2] 8c }

  condition:
    any of them
}