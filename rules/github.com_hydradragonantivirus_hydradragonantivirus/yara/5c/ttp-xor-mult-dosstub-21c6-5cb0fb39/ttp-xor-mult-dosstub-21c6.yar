rule TTP_XOR_MULT_DOSStub_21c6 {
  strings:
    $key_21c6 = { 75 ae [2] 01 b6 [2] 46 b4 [2] 01 a5 [2] 4f a9 [2] 43 a3 [2] 54 a8 [2] 4f e6 [2] 72 }

  condition:
    any of them
}