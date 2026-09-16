rule TTP_XOR_MULT_DOSStub_7ad6 {
  strings:
    $key_7ad6 = { 2e be [2] 5a a6 [2] 1d a4 [2] 5a b5 [2] 14 b9 [2] 18 b3 [2] 0f b8 [2] 14 f6 [2] 29 }

  condition:
    any of them
}