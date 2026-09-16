rule TTP_XOR_MULT_DOSStub_00d6 {
  strings:
    $key_00d6 = { 54 be [2] 20 a6 [2] 67 a4 [2] 20 b5 [2] 6e b9 [2] 62 b3 [2] 75 b8 [2] 6e f6 [2] 53 }

  condition:
    any of them
}