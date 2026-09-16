rule TTP_XOR_MULT_DOSStub_09d1 {
  strings:
    $key_09d1 = { 5d b9 [2] 29 a1 [2] 6e a3 [2] 29 b2 [2] 67 be [2] 6b b4 [2] 7c bf [2] 67 f1 [2] 5a }

  condition:
    any of them
}