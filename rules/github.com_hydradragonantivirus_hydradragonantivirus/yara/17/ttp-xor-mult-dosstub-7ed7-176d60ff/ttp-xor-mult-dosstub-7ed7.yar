rule TTP_XOR_MULT_DOSStub_7ed7 {
  strings:
    $key_7ed7 = { 2a bf [2] 5e a7 [2] 19 a5 [2] 5e b4 [2] 10 b8 [2] 1c b2 [2] 0b b9 [2] 10 f7 [2] 2d }

  condition:
    any of them
}