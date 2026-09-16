rule TTP_XOR_MULT_DOSStub_d5ca {
  strings:
    $key_d5ca = { 81 a2 [2] f5 ba [2] b2 b8 [2] f5 a9 [2] bb a5 [2] b7 af [2] a0 a4 [2] bb ea [2] 86 }

  condition:
    any of them
}