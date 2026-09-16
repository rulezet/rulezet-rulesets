rule TTP_XOR_MULT_DOSStub_6ac1 {
  strings:
    $key_6ac1 = { 3e a9 [2] 4a b1 [2] 0d b3 [2] 4a a2 [2] 04 ae [2] 08 a4 [2] 1f af [2] 04 e1 [2] 39 }

  condition:
    any of them
}