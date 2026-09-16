rule TTP_XOR_MULT_DOSStub_e298 {
  strings:
    $key_e298 = { b6 f0 [2] c2 e8 [2] 85 ea [2] c2 fb [2] 8c f7 [2] 80 fd [2] 97 f6 [2] 8c b8 [2] b1 }

  condition:
    any of them
}