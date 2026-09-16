rule TTP_XOR_MULT_DOSStub_e7ca {
  strings:
    $key_e7ca = { b3 a2 [2] c7 ba [2] 80 b8 [2] c7 a9 [2] 89 a5 [2] 85 af [2] 92 a4 [2] 89 ea [2] b4 }

  condition:
    any of them
}