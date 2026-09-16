rule TTP_XOR_MULT_DOSStub_19d7 {
  strings:
    $key_19d7 = { 4d bf [2] 39 a7 [2] 7e a5 [2] 39 b4 [2] 77 b8 [2] 7b b2 [2] 6c b9 [2] 77 f7 [2] 4a }

  condition:
    any of them
}