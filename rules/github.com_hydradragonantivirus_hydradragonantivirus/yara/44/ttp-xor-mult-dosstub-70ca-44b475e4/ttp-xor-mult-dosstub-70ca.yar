rule TTP_XOR_MULT_DOSStub_70ca {
  strings:
    $key_70ca = { 24 a2 [2] 50 ba [2] 17 b8 [2] 50 a9 [2] 1e a5 [2] 12 af [2] 05 a4 [2] 1e ea [2] 23 }

  condition:
    any of them
}