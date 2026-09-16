rule TTP_XOR_MULT_DOSStub_91b2 {
  strings:
    $key_91b2 = { c5 da [2] b1 c2 [2] f6 c0 [2] b1 d1 [2] ff dd [2] f3 d7 [2] e4 dc [2] ff 92 [2] c2 }

  condition:
    any of them
}