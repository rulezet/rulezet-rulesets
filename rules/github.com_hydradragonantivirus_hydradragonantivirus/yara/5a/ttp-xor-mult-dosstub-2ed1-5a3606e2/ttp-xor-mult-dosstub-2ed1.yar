rule TTP_XOR_MULT_DOSStub_2ed1 {
  strings:
    $key_2ed1 = { 7a b9 [2] 0e a1 [2] 49 a3 [2] 0e b2 [2] 40 be [2] 4c b4 [2] 5b bf [2] 40 f1 [2] 7d }

  condition:
    any of them
}