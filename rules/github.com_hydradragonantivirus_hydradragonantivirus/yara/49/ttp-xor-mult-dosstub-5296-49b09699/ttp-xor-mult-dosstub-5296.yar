rule TTP_XOR_MULT_DOSStub_5296 {
  strings:
    $key_5296 = { 06 fe [2] 72 e6 [2] 35 e4 [2] 72 f5 [2] 3c f9 [2] 30 f3 [2] 27 f8 [2] 3c b6 [2] 01 }

  condition:
    any of them
}