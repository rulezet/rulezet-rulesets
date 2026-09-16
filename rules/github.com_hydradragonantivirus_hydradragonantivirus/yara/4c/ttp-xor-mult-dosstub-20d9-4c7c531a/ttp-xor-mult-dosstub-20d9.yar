rule TTP_XOR_MULT_DOSStub_20d9 {
  strings:
    $key_20d9 = { 74 b1 [2] 00 a9 [2] 47 ab [2] 00 ba [2] 4e b6 [2] 42 bc [2] 55 b7 [2] 4e f9 [2] 73 }

  condition:
    any of them
}