rule TTP_XOR_MULT_DOSStub_81ce {
  strings:
    $key_81ce = { d5 a6 [2] a1 be [2] e6 bc [2] a1 ad [2] ef a1 [2] e3 ab [2] f4 a0 [2] ef ee [2] d2 }

  condition:
    any of them
}