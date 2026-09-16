rule TTP_XOR_MULT_DOSStub_9293 {
  strings:
    $key_9293 = { c6 fb [2] b2 e3 [2] f5 e1 [2] b2 f0 [2] fc fc [2] f0 f6 [2] e7 fd [2] fc b3 [2] c1 }

  condition:
    any of them
}