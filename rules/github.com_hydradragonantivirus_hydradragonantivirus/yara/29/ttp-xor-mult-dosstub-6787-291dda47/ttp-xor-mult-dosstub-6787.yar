rule TTP_XOR_MULT_DOSStub_6787 {
  strings:
    $key_6787 = { 33 ef [2] 47 f7 [2] 00 f5 [2] 47 e4 [2] 09 e8 [2] 05 e2 [2] 12 e9 [2] 09 a7 [2] 34 }

  condition:
    any of them
}