rule TTP_XOR_MULT_DOSStub_76ca {
  strings:
    $key_76ca = { 22 a2 [2] 56 ba [2] 11 b8 [2] 56 a9 [2] 18 a5 [2] 14 af [2] 03 a4 [2] 18 ea [2] 25 }

  condition:
    any of them
}