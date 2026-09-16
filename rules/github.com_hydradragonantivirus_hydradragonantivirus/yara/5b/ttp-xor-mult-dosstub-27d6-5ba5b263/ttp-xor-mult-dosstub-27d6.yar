rule TTP_XOR_MULT_DOSStub_27d6 {
  strings:
    $key_27d6 = { 73 be [2] 07 a6 [2] 40 a4 [2] 07 b5 [2] 49 b9 [2] 45 b3 [2] 52 b8 [2] 49 f6 [2] 74 }

  condition:
    any of them
}