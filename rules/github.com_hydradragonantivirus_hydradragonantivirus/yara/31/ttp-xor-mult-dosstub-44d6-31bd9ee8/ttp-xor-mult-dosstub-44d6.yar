rule TTP_XOR_MULT_DOSStub_44d6 {
  strings:
    $key_44d6 = { 10 be [2] 64 a6 [2] 23 a4 [2] 64 b5 [2] 2a b9 [2] 26 b3 [2] 31 b8 [2] 2a f6 [2] 17 }

  condition:
    any of them
}