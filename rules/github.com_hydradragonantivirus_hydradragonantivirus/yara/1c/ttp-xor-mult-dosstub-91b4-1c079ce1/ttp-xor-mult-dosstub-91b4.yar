rule TTP_XOR_MULT_DOSStub_91b4 {
  strings:
    $key_91b4 = { c5 dc [2] b1 c4 [2] f6 c6 [2] b1 d7 [2] ff db [2] f3 d1 [2] e4 da [2] ff 94 [2] c2 }

  condition:
    any of them
}