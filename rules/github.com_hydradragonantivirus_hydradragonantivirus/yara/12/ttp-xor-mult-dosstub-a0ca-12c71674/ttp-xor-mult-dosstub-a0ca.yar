rule TTP_XOR_MULT_DOSStub_a0ca {
  strings:
    $key_a0ca = { f4 a2 [2] 80 ba [2] c7 b8 [2] 80 a9 [2] ce a5 [2] c2 af [2] d5 a4 [2] ce ea [2] f3 }

  condition:
    any of them
}