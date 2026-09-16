rule TTP_XOR_MULT_DOSStub_0ad7 {
  strings:
    $key_0ad7 = { 5e bf [2] 2a a7 [2] 6d a5 [2] 2a b4 [2] 64 b8 [2] 68 b2 [2] 7f b9 [2] 64 f7 [2] 59 }

  condition:
    any of them
}