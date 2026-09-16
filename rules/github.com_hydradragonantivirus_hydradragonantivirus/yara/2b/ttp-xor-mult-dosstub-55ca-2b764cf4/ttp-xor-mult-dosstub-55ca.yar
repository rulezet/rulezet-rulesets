rule TTP_XOR_MULT_DOSStub_55ca {
  strings:
    $key_55ca = { 01 a2 [2] 75 ba [2] 32 b8 [2] 75 a9 [2] 3b a5 [2] 37 af [2] 20 a4 [2] 3b ea [2] 06 }

  condition:
    any of them
}