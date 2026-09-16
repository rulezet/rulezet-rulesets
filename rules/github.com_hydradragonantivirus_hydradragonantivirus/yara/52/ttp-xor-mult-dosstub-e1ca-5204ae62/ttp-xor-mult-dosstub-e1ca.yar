rule TTP_XOR_MULT_DOSStub_e1ca {
  strings:
    $key_e1ca = { b5 a2 [2] c1 ba [2] 86 b8 [2] c1 a9 [2] 8f a5 [2] 83 af [2] 94 a4 [2] 8f ea [2] b2 }

  condition:
    any of them
}