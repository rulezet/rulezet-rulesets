rule TTP_XOR_MULT_DOSStub_d798 {
  strings:
    $key_d798 = { 83 f0 [2] f7 e8 [2] b0 ea [2] f7 fb [2] b9 f7 [2] b5 fd [2] a2 f6 [2] b9 b8 [2] 84 }

  condition:
    any of them
}