rule TTP_XOR_MULT_DOSStub_819e {
  strings:
    $key_819e = { d5 f6 [2] a1 ee [2] e6 ec [2] a1 fd [2] ef f1 [2] e3 fb [2] f4 f0 [2] ef be [2] d2 }

  condition:
    any of them
}