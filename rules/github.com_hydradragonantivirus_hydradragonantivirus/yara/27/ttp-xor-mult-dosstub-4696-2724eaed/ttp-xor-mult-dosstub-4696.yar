rule TTP_XOR_MULT_DOSStub_4696 {
  strings:
    $key_4696 = { 12 fe [2] 66 e6 [2] 21 e4 [2] 66 f5 [2] 28 f9 [2] 24 f3 [2] 33 f8 [2] 28 b6 [2] 15 }

  condition:
    any of them
}