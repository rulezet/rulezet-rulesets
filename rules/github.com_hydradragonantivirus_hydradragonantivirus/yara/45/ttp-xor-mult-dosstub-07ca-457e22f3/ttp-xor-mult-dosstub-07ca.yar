rule TTP_XOR_MULT_DOSStub_07ca {
  strings:
    $key_07ca = { 53 a2 [2] 27 ba [2] 60 b8 [2] 27 a9 [2] 69 a5 [2] 65 af [2] 72 a4 [2] 69 ea [2] 54 }

  condition:
    any of them
}