rule TTP_XOR_MULT_DOSStub_9b8d {
  strings:
    $key_9b8d = { cf e5 [2] bb fd [2] fc ff [2] bb ee [2] f5 e2 [2] f9 e8 [2] ee e3 [2] f5 ad [2] c8 }

  condition:
    any of them
}