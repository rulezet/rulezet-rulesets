rule TTP_XOR_MULT_DOSStub_92ca {
  strings:
    $key_92ca = { c6 a2 [2] b2 ba [2] f5 b8 [2] b2 a9 [2] fc a5 [2] f0 af [2] e7 a4 [2] fc ea [2] c1 }

  condition:
    any of them
}