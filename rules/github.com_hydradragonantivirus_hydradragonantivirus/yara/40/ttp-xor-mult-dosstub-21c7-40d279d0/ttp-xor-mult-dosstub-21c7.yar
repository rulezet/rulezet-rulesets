rule TTP_XOR_MULT_DOSStub_21c7 {
  strings:
    $key_21c7 = { 75 af [2] 01 b7 [2] 46 b5 [2] 01 a4 [2] 4f a8 [2] 43 a2 [2] 54 a9 [2] 4f e7 [2] 72 }

  condition:
    any of them
}