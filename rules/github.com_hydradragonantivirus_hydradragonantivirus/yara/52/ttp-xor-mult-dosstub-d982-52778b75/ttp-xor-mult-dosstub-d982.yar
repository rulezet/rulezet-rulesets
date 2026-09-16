rule TTP_XOR_MULT_DOSStub_d982 {
  strings:
    $key_d982 = { 8d ea [2] f9 f2 [2] be f0 [2] f9 e1 [2] b7 ed [2] bb e7 [2] ac ec [2] b7 a2 [2] 8a }

  condition:
    any of them
}