rule TTP_XOR_MULT_DOSStub_c19d {
  strings:
    $key_c19d = { 95 f5 [2] e1 ed [2] a6 ef [2] e1 fe [2] af f2 [2] a3 f8 [2] b4 f3 [2] af bd [2] 92 }

  condition:
    any of them
}