rule TTP_XOR_MULT_DOSStub_31c7 {
  strings:
    $key_31c7 = { 65 af [2] 11 b7 [2] 56 b5 [2] 11 a4 [2] 5f a8 [2] 53 a2 [2] 44 a9 [2] 5f e7 [2] 62 }

  condition:
    any of them
}