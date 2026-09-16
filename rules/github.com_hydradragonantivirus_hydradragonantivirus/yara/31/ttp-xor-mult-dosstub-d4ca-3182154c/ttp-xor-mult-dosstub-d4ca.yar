rule TTP_XOR_MULT_DOSStub_d4ca {
  strings:
    $key_d4ca = { 80 a2 [2] f4 ba [2] b3 b8 [2] f4 a9 [2] ba a5 [2] b6 af [2] a1 a4 [2] ba ea [2] 87 }

  condition:
    any of them
}