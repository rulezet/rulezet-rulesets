rule TTP_XOR_MULT_DOSStub_7298 {
  strings:
    $key_7298 = { 26 f0 [2] 52 e8 [2] 15 ea [2] 52 fb [2] 1c f7 [2] 10 fd [2] 07 f6 [2] 1c b8 [2] 21 }

  condition:
    any of them
}