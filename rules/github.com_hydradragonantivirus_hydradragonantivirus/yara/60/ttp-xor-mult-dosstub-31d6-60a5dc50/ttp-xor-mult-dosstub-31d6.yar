rule TTP_XOR_MULT_DOSStub_31d6 {
  strings:
    $key_31d6 = { 65 be [2] 11 a6 [2] 56 a4 [2] 11 b5 [2] 5f b9 [2] 53 b3 [2] 44 b8 [2] 5f f6 [2] 62 }

  condition:
    any of them
}