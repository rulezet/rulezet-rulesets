rule TTP_XOR_MULT_DOSStub_3dc7 {
  strings:
    $key_3dc7 = { 69 af [2] 1d b7 [2] 5a b5 [2] 1d a4 [2] 53 a8 [2] 5f a2 [2] 48 a9 [2] 53 e7 [2] 6e }

  condition:
    any of them
}