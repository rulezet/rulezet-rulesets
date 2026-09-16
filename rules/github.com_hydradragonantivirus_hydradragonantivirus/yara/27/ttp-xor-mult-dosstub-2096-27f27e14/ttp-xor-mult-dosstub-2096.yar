rule TTP_XOR_MULT_DOSStub_2096 {
  strings:
    $key_2096 = { 74 fe [2] 00 e6 [2] 47 e4 [2] 00 f5 [2] 4e f9 [2] 42 f3 [2] 55 f8 [2] 4e b6 [2] 73 }

  condition:
    any of them
}