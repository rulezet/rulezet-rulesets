rule TTP_XOR_MULT_DOSStub_17ca {
  strings:
    $key_17ca = { 43 a2 [2] 37 ba [2] 70 b8 [2] 37 a9 [2] 79 a5 [2] 75 af [2] 62 a4 [2] 79 ea [2] 44 }

  condition:
    any of them
}