rule TTP_XOR_MULT_DOSStub_0dc6 {
  strings:
    $key_0dc6 = { 59 ae [2] 2d b6 [2] 6a b4 [2] 2d a5 [2] 63 a9 [2] 6f a3 [2] 78 a8 [2] 63 e6 [2] 5e }

  condition:
    any of them
}