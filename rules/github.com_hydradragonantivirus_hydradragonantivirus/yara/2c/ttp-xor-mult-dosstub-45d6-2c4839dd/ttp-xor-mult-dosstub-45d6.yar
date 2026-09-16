rule TTP_XOR_MULT_DOSStub_45d6 {
  strings:
    $key_45d6 = { 11 be [2] 65 a6 [2] 22 a4 [2] 65 b5 [2] 2b b9 [2] 27 b3 [2] 30 b8 [2] 2b f6 [2] 16 }

  condition:
    any of them
}