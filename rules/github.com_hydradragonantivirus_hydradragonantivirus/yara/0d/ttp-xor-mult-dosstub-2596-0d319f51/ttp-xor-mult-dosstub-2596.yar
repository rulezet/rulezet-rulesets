rule TTP_XOR_MULT_DOSStub_2596 {
  strings:
    $key_2596 = { 71 fe [2] 05 e6 [2] 42 e4 [2] 05 f5 [2] 4b f9 [2] 47 f3 [2] 50 f8 [2] 4b b6 [2] 76 }

  condition:
    any of them
}