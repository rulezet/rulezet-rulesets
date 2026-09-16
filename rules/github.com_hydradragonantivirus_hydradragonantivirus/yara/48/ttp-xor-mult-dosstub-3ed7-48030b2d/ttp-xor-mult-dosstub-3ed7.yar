rule TTP_XOR_MULT_DOSStub_3ed7 {
  strings:
    $key_3ed7 = { 6a bf [2] 1e a7 [2] 59 a5 [2] 1e b4 [2] 50 b8 [2] 5c b2 [2] 4b b9 [2] 50 f7 [2] 6d }

  condition:
    any of them
}