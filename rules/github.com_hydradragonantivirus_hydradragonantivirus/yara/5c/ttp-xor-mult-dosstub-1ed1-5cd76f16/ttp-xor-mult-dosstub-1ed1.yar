rule TTP_XOR_MULT_DOSStub_1ed1 {
  strings:
    $key_1ed1 = { 4a b9 [2] 3e a1 [2] 79 a3 [2] 3e b2 [2] 70 be [2] 7c b4 [2] 6b bf [2] 70 f1 [2] 4d }

  condition:
    any of them
}