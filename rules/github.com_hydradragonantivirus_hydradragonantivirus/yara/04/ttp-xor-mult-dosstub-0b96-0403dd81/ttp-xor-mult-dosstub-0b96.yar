rule TTP_XOR_MULT_DOSStub_0b96 {
  strings:
    $key_0b96 = { 5f fe [2] 2b e6 [2] 6c e4 [2] 2b f5 [2] 65 f9 [2] 69 f3 [2] 7e f8 [2] 65 b6 [2] 58 }

  condition:
    any of them
}