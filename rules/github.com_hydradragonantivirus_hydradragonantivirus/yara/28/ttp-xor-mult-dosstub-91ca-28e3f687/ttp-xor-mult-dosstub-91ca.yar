rule TTP_XOR_MULT_DOSStub_91ca {
  strings:
    $key_91ca = { c5 a2 [2] b1 ba [2] f6 b8 [2] b1 a9 [2] ff a5 [2] f3 af [2] e4 a4 [2] ff ea [2] c2 }

  condition:
    any of them
}