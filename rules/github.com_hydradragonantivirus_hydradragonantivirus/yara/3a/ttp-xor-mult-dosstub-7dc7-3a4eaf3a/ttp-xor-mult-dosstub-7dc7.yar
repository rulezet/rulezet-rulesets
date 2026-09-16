rule TTP_XOR_MULT_DOSStub_7dc7 {
  strings:
    $key_7dc7 = { 29 af [2] 5d b7 [2] 1a b5 [2] 5d a4 [2] 13 a8 [2] 1f a2 [2] 08 a9 [2] 13 e7 [2] 2e }

  condition:
    any of them
}