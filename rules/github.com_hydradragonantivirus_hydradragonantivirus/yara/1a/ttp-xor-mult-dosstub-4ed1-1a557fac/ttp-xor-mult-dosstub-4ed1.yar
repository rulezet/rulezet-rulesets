rule TTP_XOR_MULT_DOSStub_4ed1 {
  strings:
    $key_4ed1 = { 1a b9 [2] 6e a1 [2] 29 a3 [2] 6e b2 [2] 20 be [2] 2c b4 [2] 3b bf [2] 20 f1 [2] 1d }

  condition:
    any of them
}