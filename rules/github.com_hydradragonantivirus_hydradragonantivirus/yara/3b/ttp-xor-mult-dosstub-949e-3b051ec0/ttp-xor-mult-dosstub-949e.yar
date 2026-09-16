rule TTP_XOR_MULT_DOSStub_949e {
  strings:
    $key_949e = { c0 f6 [2] b4 ee [2] f3 ec [2] b4 fd [2] fa f1 [2] f6 fb [2] e1 f0 [2] fa be [2] c7 }

  condition:
    any of them
}