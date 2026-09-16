rule TTP_XOR_MULT_DOSStub_da89 {
  strings:
    $key_da89 = { 8e e1 [2] fa f9 [2] bd fb [2] fa ea [2] b4 e6 [2] b8 ec [2] af e7 [2] b4 a9 [2] 89 }

  condition:
    any of them
}