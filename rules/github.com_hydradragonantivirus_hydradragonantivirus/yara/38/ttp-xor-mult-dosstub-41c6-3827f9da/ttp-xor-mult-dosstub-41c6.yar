rule TTP_XOR_MULT_DOSStub_41c6 {
  strings:
    $key_41c6 = { 15 ae [2] 61 b6 [2] 26 b4 [2] 61 a5 [2] 2f a9 [2] 23 a3 [2] 34 a8 [2] 2f e6 [2] 12 }

  condition:
    any of them
}