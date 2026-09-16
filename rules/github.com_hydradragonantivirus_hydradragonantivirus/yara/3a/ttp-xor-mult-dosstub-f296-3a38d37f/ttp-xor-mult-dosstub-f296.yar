rule TTP_XOR_MULT_DOSStub_f296 {
  strings:
    $key_f296 = { a6 fe [2] d2 e6 [2] 95 e4 [2] d2 f5 [2] 9c f9 [2] 90 f3 [2] 87 f8 [2] 9c b6 [2] a1 }

  condition:
    any of them
}