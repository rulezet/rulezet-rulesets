rule TTP_XOR_MULT_DOSStub_5096 {
  strings:
    $key_5096 = { 04 fe [2] 70 e6 [2] 37 e4 [2] 70 f5 [2] 3e f9 [2] 32 f3 [2] 25 f8 [2] 3e b6 [2] 03 }

  condition:
    any of them
}