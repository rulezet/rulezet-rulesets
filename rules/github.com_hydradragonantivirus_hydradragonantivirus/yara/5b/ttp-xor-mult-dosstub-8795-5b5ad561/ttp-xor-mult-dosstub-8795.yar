rule TTP_XOR_MULT_DOSStub_8795 {
  strings:
    $key_8795 = { d3 fd [2] a7 e5 [2] e0 e7 [2] a7 f6 [2] e9 fa [2] e5 f0 [2] f2 fb [2] e9 b5 [2] d4 }

  condition:
    any of them
}