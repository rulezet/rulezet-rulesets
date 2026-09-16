rule TTP_XOR_MULT_DOSStub_21ca {
  strings:
    $key_21ca = { 75 a2 [2] 01 ba [2] 46 b8 [2] 01 a9 [2] 4f a5 [2] 43 af [2] 54 a4 [2] 4f ea [2] 72 }

  condition:
    any of them
}