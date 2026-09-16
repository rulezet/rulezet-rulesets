rule TTP_XOR_MULT_DOSStub_0ed7 {
  strings:
    $key_0ed7 = { 5a bf [2] 2e a7 [2] 69 a5 [2] 2e b4 [2] 60 b8 [2] 6c b2 [2] 7b b9 [2] 60 f7 [2] 5d }

  condition:
    any of them
}