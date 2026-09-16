rule TTP_XOR_MULT_DOSStub_1ec1 {
  strings:
    $key_1ec1 = { 4a a9 [2] 3e b1 [2] 79 b3 [2] 3e a2 [2] 70 ae [2] 7c a4 [2] 6b af [2] 70 e1 [2] 4d }

  condition:
    any of them
}