rule TTP_XOR_MULT_DOSStub_e2ca {
  strings:
    $key_e2ca = { b6 a2 [2] c2 ba [2] 85 b8 [2] c2 a9 [2] 8c a5 [2] 80 af [2] 97 a4 [2] 8c ea [2] b1 }

  condition:
    any of them
}