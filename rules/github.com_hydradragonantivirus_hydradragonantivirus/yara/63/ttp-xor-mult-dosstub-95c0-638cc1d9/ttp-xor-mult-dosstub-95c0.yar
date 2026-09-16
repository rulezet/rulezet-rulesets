rule TTP_XOR_MULT_DOSStub_95c0 {
  strings:
    $key_95c0 = { c1 a8 [2] b5 b0 [2] f2 b2 [2] b5 a3 [2] fb af [2] f7 a5 [2] e0 ae [2] fb e0 [2] c6 }

  condition:
    any of them
}