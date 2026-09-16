rule TTP_XOR_MULT_DOSStub_5bc7 {
  strings:
    $key_5bc7 = { 0f af [2] 7b b7 [2] 3c b5 [2] 7b a4 [2] 35 a8 [2] 39 a2 [2] 2e a9 [2] 35 e7 [2] 08 }

  condition:
    any of them
}