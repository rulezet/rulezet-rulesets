rule TTP_XOR_MULT_DOSStub_40ca {
  strings:
    $key_40ca = { 14 a2 [2] 60 ba [2] 27 b8 [2] 60 a9 [2] 2e a5 [2] 22 af [2] 35 a4 [2] 2e ea [2] 13 }

  condition:
    any of them
}