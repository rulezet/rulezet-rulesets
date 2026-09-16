rule TTP_XOR_MULT_DOSStub_5596 {
  strings:
    $key_5596 = { 01 fe [2] 75 e6 [2] 32 e4 [2] 75 f5 [2] 3b f9 [2] 37 f3 [2] 20 f8 [2] 3b b6 [2] 06 }

  condition:
    any of them
}