rule TTP_XOR_MULT_DOSStub_3298 {
  strings:
    $key_3298 = { 66 f0 [2] 12 e8 [2] 55 ea [2] 12 fb [2] 5c f7 [2] 50 fd [2] 47 f6 [2] 5c b8 [2] 61 }

  condition:
    any of them
}