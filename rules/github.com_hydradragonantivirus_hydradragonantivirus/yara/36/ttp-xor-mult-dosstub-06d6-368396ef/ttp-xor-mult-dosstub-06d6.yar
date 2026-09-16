rule TTP_XOR_MULT_DOSStub_06d6 {
  strings:
    $key_06d6 = { 52 be [2] 26 a6 [2] 61 a4 [2] 26 b5 [2] 68 b9 [2] 64 b3 [2] 73 b8 [2] 68 f6 [2] 55 }

  condition:
    any of them
}