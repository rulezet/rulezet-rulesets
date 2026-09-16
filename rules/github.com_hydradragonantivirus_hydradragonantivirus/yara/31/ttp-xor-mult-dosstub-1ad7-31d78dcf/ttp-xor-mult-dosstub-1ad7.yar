rule TTP_XOR_MULT_DOSStub_1ad7 {
  strings:
    $key_1ad7 = { 4e bf [2] 3a a7 [2] 7d a5 [2] 3a b4 [2] 74 b8 [2] 78 b2 [2] 6f b9 [2] 74 f7 [2] 49 }

  condition:
    any of them
}