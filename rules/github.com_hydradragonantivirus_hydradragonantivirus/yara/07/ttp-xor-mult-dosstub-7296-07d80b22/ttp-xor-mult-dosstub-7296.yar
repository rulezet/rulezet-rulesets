rule TTP_XOR_MULT_DOSStub_7296 {
  strings:
    $key_7296 = { 26 fe [2] 52 e6 [2] 15 e4 [2] 52 f5 [2] 1c f9 [2] 10 f3 [2] 07 f8 [2] 1c b6 [2] 21 }

  condition:
    any of them
}