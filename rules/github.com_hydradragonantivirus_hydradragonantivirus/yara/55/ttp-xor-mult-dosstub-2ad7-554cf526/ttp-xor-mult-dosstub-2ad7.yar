rule TTP_XOR_MULT_DOSStub_2ad7 {
  strings:
    $key_2ad7 = { 7e bf [2] 0a a7 [2] 4d a5 [2] 0a b4 [2] 44 b8 [2] 48 b2 [2] 5f b9 [2] 44 f7 [2] 79 }

  condition:
    any of them
}