rule TTP_XOR_MULT_DOSStub_7dc6 {
  strings:
    $key_7dc6 = { 29 ae [2] 5d b6 [2] 1a b4 [2] 5d a5 [2] 13 a9 [2] 1f a3 [2] 08 a8 [2] 13 e6 [2] 2e }

  condition:
    any of them
}