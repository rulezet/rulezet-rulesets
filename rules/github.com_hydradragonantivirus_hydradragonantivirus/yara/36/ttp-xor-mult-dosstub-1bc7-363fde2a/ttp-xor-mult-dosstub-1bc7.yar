rule TTP_XOR_MULT_DOSStub_1bc7 {
  strings:
    $key_1bc7 = { 4f af [2] 3b b7 [2] 7c b5 [2] 3b a4 [2] 75 a8 [2] 79 a2 [2] 6e a9 [2] 75 e7 [2] 48 }

  condition:
    any of them
}