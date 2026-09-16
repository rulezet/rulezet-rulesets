rule TTP_XOR_MULT_DOSStub_0298 {
  strings:
    $key_0298 = { 56 f0 [2] 22 e8 [2] 65 ea [2] 22 fb [2] 6c f7 [2] 60 fd [2] 77 f6 [2] 6c b8 [2] 51 }

  condition:
    any of them
}