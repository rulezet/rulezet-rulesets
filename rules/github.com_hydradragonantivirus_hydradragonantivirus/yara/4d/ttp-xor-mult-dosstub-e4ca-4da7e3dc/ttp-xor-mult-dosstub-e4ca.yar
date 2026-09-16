rule TTP_XOR_MULT_DOSStub_e4ca {
  strings:
    $key_e4ca = { b0 a2 [2] c4 ba [2] 83 b8 [2] c4 a9 [2] 8a a5 [2] 86 af [2] 91 a4 [2] 8a ea [2] b7 }

  condition:
    any of them
}