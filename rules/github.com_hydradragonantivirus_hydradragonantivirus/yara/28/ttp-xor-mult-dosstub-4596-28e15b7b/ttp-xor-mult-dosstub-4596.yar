rule TTP_XOR_MULT_DOSStub_4596 {
  strings:
    $key_4596 = { 11 fe [2] 65 e6 [2] 22 e4 [2] 65 f5 [2] 2b f9 [2] 27 f3 [2] 30 f8 [2] 2b b6 [2] 16 }

  condition:
    any of them
}