rule TTP_XOR_MULT_DOSStub_9093 {
  strings:
    $key_9093 = { c4 fb [2] b0 e3 [2] f7 e1 [2] b0 f0 [2] fe fc [2] f2 f6 [2] e5 fd [2] fe b3 [2] c3 }

  condition:
    any of them
}