rule TTP_XOR_MULT_DOSStub_5bc6 {
  strings:
    $key_5bc6 = { 0f ae [2] 7b b6 [2] 3c b4 [2] 7b a5 [2] 35 a9 [2] 39 a3 [2] 2e a8 [2] 35 e6 [2] 08 }

  condition:
    any of them
}