rule TTP_XOR_MULT_DOSStub_71d6 {
  strings:
    $key_71d6 = { 25 be [2] 51 a6 [2] 16 a4 [2] 51 b5 [2] 1f b9 [2] 13 b3 [2] 04 b8 [2] 1f f6 [2] 22 }

  condition:
    any of them
}