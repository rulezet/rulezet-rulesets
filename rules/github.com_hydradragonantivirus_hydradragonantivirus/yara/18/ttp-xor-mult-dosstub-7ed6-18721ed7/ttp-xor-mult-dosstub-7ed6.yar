rule TTP_XOR_MULT_DOSStub_7ed6 {
  strings:
    $key_7ed6 = { 2a be [2] 5e a6 [2] 19 a4 [2] 5e b5 [2] 10 b9 [2] 1c b3 [2] 0b b8 [2] 10 f6 [2] 2d }

  condition:
    any of them
}