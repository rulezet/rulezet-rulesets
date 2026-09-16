rule TTP_XOR_MULT_DOSStub_56ca {
  strings:
    $key_56ca = { 02 a2 [2] 76 ba [2] 31 b8 [2] 76 a9 [2] 38 a5 [2] 34 af [2] 23 a4 [2] 38 ea [2] 05 }

  condition:
    any of them
}