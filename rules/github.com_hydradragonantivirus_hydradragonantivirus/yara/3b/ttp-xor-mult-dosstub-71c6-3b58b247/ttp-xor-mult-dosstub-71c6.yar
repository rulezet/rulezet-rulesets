rule TTP_XOR_MULT_DOSStub_71c6 {
  strings:
    $key_71c6 = { 25 ae [2] 51 b6 [2] 16 b4 [2] 51 a5 [2] 1f a9 [2] 13 a3 [2] 04 a8 [2] 1f e6 [2] 22 }

  condition:
    any of them
}