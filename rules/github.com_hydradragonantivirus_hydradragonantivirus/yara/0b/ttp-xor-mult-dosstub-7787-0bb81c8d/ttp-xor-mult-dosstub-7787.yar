rule TTP_XOR_MULT_DOSStub_7787 {
  strings:
    $key_7787 = { 23 ef [2] 57 f7 [2] 10 f5 [2] 57 e4 [2] 19 e8 [2] 15 e2 [2] 02 e9 [2] 19 a7 [2] 24 }

  condition:
    any of them
}