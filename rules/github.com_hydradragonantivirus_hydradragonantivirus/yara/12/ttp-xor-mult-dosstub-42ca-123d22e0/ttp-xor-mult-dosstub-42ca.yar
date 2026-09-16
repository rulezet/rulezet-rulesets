rule TTP_XOR_MULT_DOSStub_42ca {
  strings:
    $key_42ca = { 16 a2 [2] 62 ba [2] 25 b8 [2] 62 a9 [2] 2c a5 [2] 20 af [2] 37 a4 [2] 2c ea [2] 11 }

  condition:
    any of them
}