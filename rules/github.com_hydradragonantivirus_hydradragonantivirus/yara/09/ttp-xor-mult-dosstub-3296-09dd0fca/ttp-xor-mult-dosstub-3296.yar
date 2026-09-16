rule TTP_XOR_MULT_DOSStub_3296 {
  strings:
    $key_3296 = { 66 fe [2] 12 e6 [2] 55 e4 [2] 12 f5 [2] 5c f9 [2] 50 f3 [2] 47 f8 [2] 5c b6 [2] 61 }

  condition:
    any of them
}