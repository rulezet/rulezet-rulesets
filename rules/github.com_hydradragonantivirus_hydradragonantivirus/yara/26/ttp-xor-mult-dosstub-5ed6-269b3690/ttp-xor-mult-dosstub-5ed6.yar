rule TTP_XOR_MULT_DOSStub_5ed6 {
  strings:
    $key_5ed6 = { 0a be [2] 7e a6 [2] 39 a4 [2] 7e b5 [2] 30 b9 [2] 3c b3 [2] 2b b8 [2] 30 f6 [2] 0d }

  condition:
    any of them
}