rule TTP_XOR_MULT_DOSStub_86aa {
  strings:
    $key_86aa = { d2 c2 [2] a6 da [2] e1 d8 [2] a6 c9 [2] e8 c5 [2] e4 cf [2] f3 c4 [2] e8 8a [2] d5 }

  condition:
    any of them
}