rule TTP_XOR_MULT_DOSStub_4ed6 {
  strings:
    $key_4ed6 = { 1a be [2] 6e a6 [2] 29 a4 [2] 6e b5 [2] 20 b9 [2] 2c b3 [2] 3b b8 [2] 20 f6 [2] 1d }

  condition:
    any of them
}