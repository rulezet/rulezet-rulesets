rule TTP_XOR_MULT_DOSStub_d9b1 {
  strings:
    $key_d9b1 = { 8d d9 [2] f9 c1 [2] be c3 [2] f9 d2 [2] b7 de [2] bb d4 [2] ac df [2] b7 91 [2] 8a }

  condition:
    any of them
}