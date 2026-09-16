rule TTP_XOR_MULT_DOSStub_a7ca {
  strings:
    $key_a7ca = { f3 a2 [2] 87 ba [2] c0 b8 [2] 87 a9 [2] c9 a5 [2] c5 af [2] d2 a4 [2] c9 ea [2] f4 }

  condition:
    any of them
}