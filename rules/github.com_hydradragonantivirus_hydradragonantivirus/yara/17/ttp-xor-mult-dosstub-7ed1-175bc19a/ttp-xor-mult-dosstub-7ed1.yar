rule TTP_XOR_MULT_DOSStub_7ed1 {
  strings:
    $key_7ed1 = { 2a b9 [2] 5e a1 [2] 19 a3 [2] 5e b2 [2] 10 be [2] 1c b4 [2] 0b bf [2] 10 f1 [2] 2d }

  condition:
    any of them
}