rule TTP_XOR_MULT_DOSStub_93d2 {
  strings:
    $key_93d2 = { c7 ba [2] b3 a2 [2] f4 a0 [2] b3 b1 [2] fd bd [2] f1 b7 [2] e6 bc [2] fd f2 [2] c0 }

  condition:
    any of them
}