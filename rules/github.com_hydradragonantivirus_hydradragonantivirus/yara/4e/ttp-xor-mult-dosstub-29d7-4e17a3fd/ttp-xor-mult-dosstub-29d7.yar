rule TTP_XOR_MULT_DOSStub_29d7 {
  strings:
    $key_29d7 = { 7d bf [2] 09 a7 [2] 4e a5 [2] 09 b4 [2] 47 b8 [2] 4b b2 [2] 5c b9 [2] 47 f7 [2] 7a }

  condition:
    any of them
}