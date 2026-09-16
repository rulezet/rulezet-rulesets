rule TTP_XOR_MULT_DOSStub_36ca {
  strings:
    $key_36ca = { 62 a2 [2] 16 ba [2] 51 b8 [2] 16 a9 [2] 58 a5 [2] 54 af [2] 43 a4 [2] 58 ea [2] 65 }

  condition:
    any of them
}