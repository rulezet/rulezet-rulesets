rule TTP_XOR_MULT_DOSStub_9693 {
  strings:
    $key_9693 = { c2 fb [2] b6 e3 [2] f1 e1 [2] b6 f0 [2] f8 fc [2] f4 f6 [2] e3 fd [2] f8 b3 [2] c5 }

  condition:
    any of them
}