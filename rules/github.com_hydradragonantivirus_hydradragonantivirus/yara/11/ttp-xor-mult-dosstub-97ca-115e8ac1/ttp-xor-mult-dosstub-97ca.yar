rule TTP_XOR_MULT_DOSStub_97ca {
  strings:
    $key_97ca = { c3 a2 [2] b7 ba [2] f0 b8 [2] b7 a9 [2] f9 a5 [2] f5 af [2] e2 a4 [2] f9 ea [2] c4 }

  condition:
    any of them
}