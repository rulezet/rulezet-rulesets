rule TTP_XOR_MULT_DOSStub_0eb1 {
  strings:
    $key_0eb1 = { 5a d9 [2] 2e c1 [2] 69 c3 [2] 2e d2 [2] 60 de [2] 6c d4 [2] 7b df [2] 60 91 [2] 5d }

  condition:
    any of them
}