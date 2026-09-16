rule TTP_XOR_MULT_DOSStub_01d6 {
  strings:
    $key_01d6 = { 55 be [2] 21 a6 [2] 66 a4 [2] 21 b5 [2] 6f b9 [2] 63 b3 [2] 74 b8 [2] 6f f6 [2] 52 }

  condition:
    any of them
}