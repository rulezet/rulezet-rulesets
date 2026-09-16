rule TTP_XOR_MULT_DOSStub_4bc7 {
  strings:
    $key_4bc7 = { 1f af [2] 6b b7 [2] 2c b5 [2] 6b a4 [2] 25 a8 [2] 29 a2 [2] 3e a9 [2] 25 e7 [2] 18 }

  condition:
    any of them
}