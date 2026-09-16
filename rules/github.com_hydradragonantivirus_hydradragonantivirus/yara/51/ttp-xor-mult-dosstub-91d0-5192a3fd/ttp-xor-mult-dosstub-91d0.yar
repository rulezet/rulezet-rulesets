rule TTP_XOR_MULT_DOSStub_91d0 {
  strings:
    $key_91d0 = { c5 b8 [2] b1 a0 [2] f6 a2 [2] b1 b3 [2] ff bf [2] f3 b5 [2] e4 be [2] ff f0 [2] c2 }

  condition:
    any of them
}