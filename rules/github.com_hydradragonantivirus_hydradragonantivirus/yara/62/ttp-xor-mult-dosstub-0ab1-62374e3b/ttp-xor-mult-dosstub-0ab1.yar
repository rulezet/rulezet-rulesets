rule TTP_XOR_MULT_DOSStub_0ab1 {
  strings:
    $key_0ab1 = { 5e d9 [2] 2a c1 [2] 6d c3 [2] 2a d2 [2] 64 de [2] 68 d4 [2] 7f df [2] 64 91 [2] 59 }

  condition:
    any of them
}