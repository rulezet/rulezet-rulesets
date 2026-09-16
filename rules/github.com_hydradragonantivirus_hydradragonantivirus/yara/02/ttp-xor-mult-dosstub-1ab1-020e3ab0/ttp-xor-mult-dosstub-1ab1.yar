rule TTP_XOR_MULT_DOSStub_1ab1 {
  strings:
    $key_1ab1 = { 4e d9 [2] 3a c1 [2] 7d c3 [2] 3a d2 [2] 74 de [2] 78 d4 [2] 6f df [2] 74 91 [2] 49 }

  condition:
    any of them
}