rule TTP_XOR_MULT_DOSStub_51c6 {
  strings:
    $key_51c6 = { 05 ae [2] 71 b6 [2] 36 b4 [2] 71 a5 [2] 3f a9 [2] 33 a3 [2] 24 a8 [2] 3f e6 [2] 02 }

  condition:
    any of them
}