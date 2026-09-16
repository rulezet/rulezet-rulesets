rule TTP_XOR_MULT_DOSStub_1eb1 {
  strings:
    $key_1eb1 = { 4a d9 [2] 3e c1 [2] 79 c3 [2] 3e d2 [2] 70 de [2] 7c d4 [2] 6b df [2] 70 91 [2] 4d }

  condition:
    any of them
}