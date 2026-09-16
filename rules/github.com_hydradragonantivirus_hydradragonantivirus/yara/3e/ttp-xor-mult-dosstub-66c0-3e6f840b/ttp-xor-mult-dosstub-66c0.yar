rule TTP_XOR_MULT_DOSStub_66c0 {
  strings:
    $key_66c0 = { 32 a8 [2] 46 b0 [2] 01 b2 [2] 46 a3 [2] 08 af [2] 04 a5 [2] 13 ae [2] 08 e0 [2] 35 }

  condition:
    any of them
}