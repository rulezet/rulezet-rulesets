rule TTP_XOR_MULT_DOSStub_2eb1 {
  strings:
    $key_2eb1 = { 7a d9 [2] 0e c1 [2] 49 c3 [2] 0e d2 [2] 40 de [2] 4c d4 [2] 5b df [2] 40 91 [2] 7d }

  condition:
    any of them
}