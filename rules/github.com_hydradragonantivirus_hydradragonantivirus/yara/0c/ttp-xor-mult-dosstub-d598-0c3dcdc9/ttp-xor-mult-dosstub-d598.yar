rule TTP_XOR_MULT_DOSStub_d598 {
  strings:
    $key_d598 = { 81 f0 [2] f5 e8 [2] b2 ea [2] f5 fb [2] bb f7 [2] b7 fd [2] a0 f6 [2] bb b8 [2] 86 }

  condition:
    any of them
}