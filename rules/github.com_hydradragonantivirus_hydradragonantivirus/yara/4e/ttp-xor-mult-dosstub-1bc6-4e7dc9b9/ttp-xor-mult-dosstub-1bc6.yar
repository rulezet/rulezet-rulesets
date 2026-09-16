rule TTP_XOR_MULT_DOSStub_1bc6 {
  strings:
    $key_1bc6 = { 4f ae [2] 3b b6 [2] 7c b4 [2] 3b a5 [2] 75 a9 [2] 79 a3 [2] 6e a8 [2] 75 e6 [2] 48 }

  condition:
    any of them
}