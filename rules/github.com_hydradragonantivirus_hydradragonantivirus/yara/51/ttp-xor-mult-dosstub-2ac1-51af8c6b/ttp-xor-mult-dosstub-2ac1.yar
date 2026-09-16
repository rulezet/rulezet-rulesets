rule TTP_XOR_MULT_DOSStub_2ac1 {
  strings:
    $key_2ac1 = { 7e a9 [2] 0a b1 [2] 4d b3 [2] 0a a2 [2] 44 ae [2] 48 a4 [2] 5f af [2] 44 e1 [2] 79 }

  condition:
    any of them
}