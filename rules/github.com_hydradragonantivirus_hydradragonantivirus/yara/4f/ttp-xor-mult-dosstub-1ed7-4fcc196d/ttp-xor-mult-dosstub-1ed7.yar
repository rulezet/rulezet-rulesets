rule TTP_XOR_MULT_DOSStub_1ed7 {
  strings:
    $key_1ed7 = { 4a bf [2] 3e a7 [2] 79 a5 [2] 3e b4 [2] 70 b8 [2] 7c b2 [2] 6b b9 [2] 70 f7 [2] 4d }

  condition:
    any of them
}