rule TTP_XOR_MULT_DOSStub_81aa {
  strings:
    $key_81aa = { d5 c2 [2] a1 da [2] e6 d8 [2] a1 c9 [2] ef c5 [2] e3 cf [2] f4 c4 [2] ef 8a [2] d2 }

  condition:
    any of them
}