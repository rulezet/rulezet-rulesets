rule TTP_XOR_MULT_DOSStub_7bc7 {
  strings:
    $key_7bc7 = { 2f af [2] 5b b7 [2] 1c b5 [2] 5b a4 [2] 15 a8 [2] 19 a2 [2] 0e a9 [2] 15 e7 [2] 28 }

  condition:
    any of them
}