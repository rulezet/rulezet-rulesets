rule TTP_XOR_MULT_DOSStub_24d6 {
  strings:
    $key_24d6 = { 70 be [2] 04 a6 [2] 43 a4 [2] 04 b5 [2] 4a b9 [2] 46 b3 [2] 51 b8 [2] 4a f6 [2] 77 }

  condition:
    any of them
}