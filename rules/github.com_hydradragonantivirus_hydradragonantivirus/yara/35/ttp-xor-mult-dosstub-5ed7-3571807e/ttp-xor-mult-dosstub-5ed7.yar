rule TTP_XOR_MULT_DOSStub_5ed7 {
  strings:
    $key_5ed7 = { 0a bf [2] 7e a7 [2] 39 a5 [2] 7e b4 [2] 30 b8 [2] 3c b2 [2] 2b b9 [2] 30 f7 [2] 0d }

  condition:
    any of them
}