rule TTP_XOR_MULT_DOSStub_dfc7 {
  strings:
    $key_dfc7 = { 8b af [2] ff b7 [2] b8 b5 [2] ff a4 [2] b1 a8 [2] bd a2 [2] aa a9 [2] b1 e7 [2] 8c }

  condition:
    any of them
}