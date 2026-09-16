rule TTP_XOR_MULT_DOSStub_25d6 {
  strings:
    $key_25d6 = { 71 be [2] 05 a6 [2] 42 a4 [2] 05 b5 [2] 4b b9 [2] 47 b3 [2] 50 b8 [2] 4b f6 [2] 76 }

  condition:
    any of them
}