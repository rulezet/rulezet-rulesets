rule TTP_XOR_MULT_DOSStub_7ac1 {
  strings:
    $key_7ac1 = { 2e a9 [2] 5a b1 [2] 1d b3 [2] 5a a2 [2] 14 ae [2] 18 a4 [2] 0f af [2] 14 e1 [2] 29 }

  condition:
    any of them
}