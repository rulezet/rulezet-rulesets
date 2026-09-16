rule TTP_XOR_MULT_DOSStub_66d6 {
  strings:
    $key_66d6 = { 32 be [2] 46 a6 [2] 01 a4 [2] 46 b5 [2] 08 b9 [2] 04 b3 [2] 13 b8 [2] 08 f6 [2] 35 }

  condition:
    any of them
}