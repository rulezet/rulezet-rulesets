rule TTP_XOR_MULT_DOSStub_65d6 {
  strings:
    $key_65d6 = { 31 be [2] 45 a6 [2] 02 a4 [2] 45 b5 [2] 0b b9 [2] 07 b3 [2] 10 b8 [2] 0b f6 [2] 36 }

  condition:
    any of them
}