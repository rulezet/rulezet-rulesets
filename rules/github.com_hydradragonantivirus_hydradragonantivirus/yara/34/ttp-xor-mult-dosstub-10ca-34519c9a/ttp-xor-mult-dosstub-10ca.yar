rule TTP_XOR_MULT_DOSStub_10ca {
  strings:
    $key_10ca = { 44 a2 [2] 30 ba [2] 77 b8 [2] 30 a9 [2] 7e a5 [2] 72 af [2] 65 a4 [2] 7e ea [2] 43 }

  condition:
    any of them
}