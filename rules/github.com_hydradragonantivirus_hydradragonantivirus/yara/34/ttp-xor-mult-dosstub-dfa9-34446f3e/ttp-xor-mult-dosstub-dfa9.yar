rule TTP_XOR_MULT_DOSStub_dfa9 {
  strings:
    $key_dfa9 = { 8b c1 [2] ff d9 [2] b8 db [2] ff ca [2] b1 c6 [2] bd cc [2] aa c7 [2] b1 89 [2] 8c }

  condition:
    any of them
}