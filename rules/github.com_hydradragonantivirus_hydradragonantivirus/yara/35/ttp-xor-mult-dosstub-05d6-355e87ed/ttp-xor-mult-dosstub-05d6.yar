rule TTP_XOR_MULT_DOSStub_05d6 {
  strings:
    $key_05d6 = { 51 be [2] 25 a6 [2] 62 a4 [2] 25 b5 [2] 6b b9 [2] 67 b3 [2] 70 b8 [2] 6b f6 [2] 56 }

  condition:
    any of them
}