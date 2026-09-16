rule TTP_XOR_MULT_DOSStub_66c7 {
  strings:
    $key_66c7 = { 32 af [2] 46 b7 [2] 01 b5 [2] 46 a4 [2] 08 a8 [2] 04 a2 [2] 13 a9 [2] 08 e7 [2] 35 }

  condition:
    any of them
}