rule TTP_XOR_MULT_DOSStub_dfd3 {
  strings:
    $key_dfd3 = { 8b bb [2] ff a3 [2] b8 a1 [2] ff b0 [2] b1 bc [2] bd b6 [2] aa bd [2] b1 f3 [2] 8c }

  condition:
    any of them
}