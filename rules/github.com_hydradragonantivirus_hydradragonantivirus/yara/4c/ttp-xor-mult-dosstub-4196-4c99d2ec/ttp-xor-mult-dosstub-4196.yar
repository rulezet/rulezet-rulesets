rule TTP_XOR_MULT_DOSStub_4196 {
  strings:
    $key_4196 = { 15 fe [2] 61 e6 [2] 26 e4 [2] 61 f5 [2] 2f f9 [2] 23 f3 [2] 34 f8 [2] 2f b6 [2] 12 }

  condition:
    any of them
}