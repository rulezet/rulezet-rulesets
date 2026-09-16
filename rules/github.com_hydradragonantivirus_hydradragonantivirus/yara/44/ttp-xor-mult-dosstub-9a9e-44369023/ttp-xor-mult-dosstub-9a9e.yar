rule TTP_XOR_MULT_DOSStub_9a9e {
  strings:
    $key_9a9e = { ce f6 [2] ba ee [2] fd ec [2] ba fd [2] f4 f1 [2] f8 fb [2] ef f0 [2] f4 be [2] c9 }

  condition:
    any of them
}