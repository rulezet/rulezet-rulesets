rule TTP_XOR_MULT_DOSStub_67ca {
  strings:
    $key_67ca = { 33 a2 [2] 47 ba [2] 00 b8 [2] 47 a9 [2] 09 a5 [2] 05 af [2] 12 a4 [2] 09 ea [2] 34 }

  condition:
    any of them
}