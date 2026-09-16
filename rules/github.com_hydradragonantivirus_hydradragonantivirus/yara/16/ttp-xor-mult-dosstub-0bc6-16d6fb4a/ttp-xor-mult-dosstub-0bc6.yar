rule TTP_XOR_MULT_DOSStub_0bc6 {
  strings:
    $key_0bc6 = { 5f ae [2] 2b b6 [2] 6c b4 [2] 2b a5 [2] 65 a9 [2] 69 a3 [2] 7e a8 [2] 65 e6 [2] 58 }

  condition:
    any of them
}