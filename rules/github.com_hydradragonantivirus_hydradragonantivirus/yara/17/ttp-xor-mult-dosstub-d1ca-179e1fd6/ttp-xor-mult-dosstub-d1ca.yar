rule TTP_XOR_MULT_DOSStub_d1ca {
  strings:
    $key_d1ca = { 85 a2 [2] f1 ba [2] b6 b8 [2] f1 a9 [2] bf a5 [2] b3 af [2] a4 a4 [2] bf ea [2] 82 }

  condition:
    any of them
}