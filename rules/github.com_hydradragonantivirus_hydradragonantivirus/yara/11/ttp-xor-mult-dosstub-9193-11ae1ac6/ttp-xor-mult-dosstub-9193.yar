rule TTP_XOR_MULT_DOSStub_9193 {
  strings:
    $key_9193 = { c5 fb [2] b1 e3 [2] f6 e1 [2] b1 f0 [2] ff fc [2] f3 f6 [2] e4 fd [2] ff b3 [2] c2 }

  condition:
    any of them
}