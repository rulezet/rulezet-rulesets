rule TTP_XOR_MULT_DOSStub_4bc6 {
  strings:
    $key_4bc6 = { 1f ae [2] 6b b6 [2] 2c b4 [2] 6b a5 [2] 25 a9 [2] 29 a3 [2] 3e a8 [2] 25 e6 [2] 18 }

  condition:
    any of them
}