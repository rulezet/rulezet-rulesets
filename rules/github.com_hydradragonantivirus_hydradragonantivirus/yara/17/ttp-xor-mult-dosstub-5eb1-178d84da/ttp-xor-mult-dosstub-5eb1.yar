rule TTP_XOR_MULT_DOSStub_5eb1 {
  strings:
    $key_5eb1 = { 0a d9 [2] 7e c1 [2] 39 c3 [2] 7e d2 [2] 30 de [2] 3c d4 [2] 2b df [2] 30 91 [2] 0d }

  condition:
    any of them
}