rule TTP_XOR_MULT_DOSStub_7596 {
  strings:
    $key_7596 = { 21 fe [2] 55 e6 [2] 12 e4 [2] 55 f5 [2] 1b f9 [2] 17 f3 [2] 00 f8 [2] 1b b6 [2] 26 }

  condition:
    any of them
}