rule TTP_XOR_MULT_DOSStub_5dc0 {
  strings:
    $key_5dc0 = { 09 a8 [2] 7d b0 [2] 3a b2 [2] 7d a3 [2] 33 af [2] 3f a5 [2] 28 ae [2] 33 e0 [2] 0e }

  condition:
    any of them
}