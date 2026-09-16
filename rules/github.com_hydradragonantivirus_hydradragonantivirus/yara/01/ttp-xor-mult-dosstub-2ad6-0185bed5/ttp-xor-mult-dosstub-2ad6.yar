rule TTP_XOR_MULT_DOSStub_2ad6 {
  strings:
    $key_2ad6 = { 7e be [2] 0a a6 [2] 4d a4 [2] 0a b5 [2] 44 b9 [2] 48 b3 [2] 5f b8 [2] 44 f6 [2] 79 }

  condition:
    any of them
}