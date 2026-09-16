rule TTP_XOR_MULT_DOSStub_3ed6 {
  strings:
    $key_3ed6 = { 6a be [2] 1e a6 [2] 59 a4 [2] 1e b5 [2] 50 b9 [2] 5c b3 [2] 4b b8 [2] 50 f6 [2] 6d }

  condition:
    any of them
}