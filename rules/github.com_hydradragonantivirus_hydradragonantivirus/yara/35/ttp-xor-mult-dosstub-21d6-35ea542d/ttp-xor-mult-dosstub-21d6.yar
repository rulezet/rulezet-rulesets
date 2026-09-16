rule TTP_XOR_MULT_DOSStub_21d6 {
  strings:
    $key_21d6 = { 75 be [2] 01 a6 [2] 46 a4 [2] 01 b5 [2] 4f b9 [2] 43 b3 [2] 54 b8 [2] 4f f6 [2] 72 }

  condition:
    any of them
}